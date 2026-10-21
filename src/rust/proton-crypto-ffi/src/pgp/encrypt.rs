use super::{
    DataEncoding, EncryptedMessage, Encryptor, ForeignWriter, FromId, InteropError, PrivateKey,
    Profile, SessionKey, SignatureContext, UnsafePtr, catch_error, check_unix_time,
};
use crate::pgp::keys::{PgpKey, private_keys_vec, public_keys_from_keys};
use proton_rpgp::PublicKey;
use proton_rpgp::pgp::crypto::aead::ChunkSize;
use std::borrow::Cow;
use std::io::Write;
pub(crate) mod encrypt_stream;

fn encode_message_for_output(
    message: &EncryptedMessage,
    encoding: DataEncoding,
) -> Result<Cow<'_, [u8]>, String> {
    match encoding {
        DataEncoding::Unarmored => Ok(Cow::Borrowed(message.as_ref())),
        _ => message
            .armor()
            .map(Cow::Owned)
            .map_err(|error| error.to_string()),
    }
}

#[repr(C)]
pub(crate) struct EncryptionParameters {
    pub(crate) profile: u8,
    pub(crate) encryption_keys_len: usize,
    pub(crate) signing_keys_len: usize,
    pub(crate) has_session_key: bool,
    pub(crate) has_signing_context: bool,
    pub(crate) has_encryption_time: bool,
    pub(crate) detached_sig: bool,
    pub(crate) detached_sig_encrypted: bool,
    pub(crate) utf8: bool,
    pub(crate) compress: bool,
    pub(crate) encryption_keys: *const *const PgpKey,
    pub(crate) signing_keys: *const *const PgpKey,
    pub(crate) session_key: *const SessionKey,
    pub(crate) signing_context: *const SignatureContext,
    pub(crate) encryption_time: u64,
    pub(crate) streaming_chunk_size_hint: u64,
    pub(crate) password_len: usize,
    pub(crate) password: *const u8,
}

#[derive(Clone, Copy)]
pub(crate) struct EncryptionSettings {
    profile: u8,
    has_encryption_time: bool,
    detached_sig: bool,
    detached_sig_encrypted: bool,
    utf8: bool,
    compress: bool,
    encryption_time: u64,
    streaming_chunk_size_hint: u64,
}
impl EncryptionSettings {
    pub(crate) fn build_encryptor<'a>(
        &self,
        encryption_keys: impl IntoIterator<Item = &'a PublicKey>,
        signing_keys: impl IntoIterator<Item = &'a PrivateKey>,
        session_key: Option<&'a SessionKey>,
        signing_context: Option<&'a SignatureContext>,
        password: Option<&'a [u8]>,
    ) -> Encryptor<'a> {
        let profile = Profile::from_id(self.profile);
        let mut encryptor = Encryptor::new(profile)
            .with_encryption_keys(encryption_keys)
            .with_signing_keys(signing_keys);

        if let Some(session_key) = session_key {
            encryptor = encryptor.with_session_key(session_key);
        }
        if let Some(signing_context) = signing_context {
            encryptor = encryptor.with_signature_context(signing_context);
        }
        if let Some(password) = password {
            encryptor = encryptor.with_passphrase(password);
        }
        if self.has_encryption_time {
            encryptor = encryptor.at_date(check_unix_time(self.encryption_time));
        }
        if self.compress {
            encryptor = encryptor.compress();
        }
        if self.utf8 {
            encryptor = encryptor.as_utf8();
        }
        if self.detached_sig {
            encryptor = encryptor.using_detached_signature(self.detached_sig_encrypted);
        }
        if self.streaming_chunk_size_hint > 0 {
            encryptor = encryptor
                .with_aead_chunk_size(chunk_size_from_hint(self.streaming_chunk_size_hint));
        }

        encryptor
    }
}
impl From<&EncryptionParameters> for EncryptionSettings {
    fn from(params: &EncryptionParameters) -> Self {
        Self {
            profile: params.profile,
            has_encryption_time: params.has_encryption_time,
            detached_sig: params.detached_sig,
            detached_sig_encrypted: params.detached_sig_encrypted,
            utf8: params.utf8,
            compress: params.compress,
            encryption_time: params.encryption_time,
            streaming_chunk_size_hint: params.streaming_chunk_size_hint,
        }
    }
}

impl FromId for ChunkSize {
    type Output = ChunkSize;

    fn from_id(value: u8) -> Self::Output {
        match ChunkSize::try_from(value) {
            Ok(chunk) => chunk,
            Err(_) => ChunkSize::C4MiB,
        }
    }
}

fn chunk_size_from_hint(value: u64) -> ChunkSize {
    // A hint of zero defaults to `ChunkSize::C256 KiB` to match Go.
    if value == 0 {
        ChunkSize::C256KiB
    } else {
        let size = value.ilog2().clamp(6, 22);
        // Map the chunk size in bytes to the raw enum ID.
        ChunkSize::from_id(size.saturating_sub(6) as u8)
    }
}

/// Encrypts a session key into OpenPGP key packets, writing them to `output_writer`.
///
/// Recipients and an optional password are taken from `parameters` (signing keys are ignored here);
/// `session_key` is the live session-key handle to wrap.
///
/// # Safety
/// `parameters` must be a valid non-null pointer to an initialized `EncryptionParameters` whose
/// embedded key-handle arrays and `password` pointer are valid; `session_key` must be a live
/// session-key handle; `output_writer` must be a valid host writer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_encrypt_session_key(
    parameters: *const EncryptionParameters,
    session_key: *const SessionKey,
    mut output_writer: ForeignWriter,
) -> InteropError {
    catch_error(|| {
        let params = UnsafePtr::as_ref(parameters)?;
        let keys = UnsafePtr::get_handle_slice(params.encryption_keys, params.encryption_keys_len)?;
        let encryption_keys = public_keys_from_keys(keys);
        let password = UnsafePtr::get_slice(params.password, params.password_len)?;
        let password = (!password.is_empty()).then_some(password);
        let session_key = UnsafePtr::as_ref(session_key)?;
        let encryptor = EncryptionSettings::from(params).build_encryptor(
            encryption_keys,
            &[],
            None,
            None,
            password,
        );
        let key_packets = encryptor
            .encrypt_session_key(session_key)
            .map_err(|error| error.to_string())?;
        output_writer
            .write_all(&key_packets)
            .map_err(|error| error.to_string())
    })
}

/// Encrypts (and optionally signs) a message, writing the OpenPGP output to `output_writer`.
///
/// `parameters` supplies recipients, signing keys, optional session key, signing context, password,
/// and options; `encoding` selects the output encoding (0 armored, 1 unarmored, other auto). When
/// `parameters.detached_sig` is set the detached signature is written to `signature_writer`
/// (which then must be a valid writer and signing keys must be present); otherwise it is embedded
/// and a zeroed `signature_writer` may be passed.
///
/// # Safety
/// `parameters` must be a valid non-null pointer to an initialized `EncryptionParameters` whose
/// embedded key-handle arrays, `password` pointer, and session-key/signing-context handles are
/// valid; `message` must be valid for `message_len` bytes (or null when zero); `signature_writer`
/// may be zeroed when no detached signature is requested; `output_writer` must be a valid host
/// writer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_encrypt(
    parameters: *const EncryptionParameters,
    message: *const u8,
    message_len: usize,
    encoding: u8,
    signature_writer: ForeignWriter,
    mut output_writer: ForeignWriter,
) -> InteropError {
    catch_error(|| {
        let encoding = DataEncoding::from_id(encoding)?;
        let params = UnsafePtr::as_ref(parameters)?;
        let keys = UnsafePtr::get_handle_slice(params.encryption_keys, params.encryption_keys_len)?;
        let encryption_keys = public_keys_from_keys(keys).collect::<Vec<&PublicKey>>();
        let signing_keys = private_keys_vec(params.signing_keys, params.signing_keys_len)?;
        let password = UnsafePtr::get_slice(params.password, params.password_len)?;
        let password = (!password.is_empty()).then_some(password);
        let session_key = UnsafePtr::maybe_ref(params.session_key, params.has_session_key)?;
        let signing_context =
            UnsafePtr::maybe_ref(params.signing_context, params.has_signing_context)?;
        let message = UnsafePtr::get_slice(message, message_len)?;
        let encryptor = EncryptionSettings::from(params).build_encryptor(
            encryption_keys,
            signing_keys.iter().copied(),
            session_key,
            signing_context,
            password,
        );

        if params.detached_sig {
            require_detached_signature_sink(signature_writer, !signing_keys.is_empty())?;

            let encrypted = encryptor
                .encrypt(message)
                .map_err(|error| error.to_string())?;
            let encoded_message = encode_message_for_output(&encrypted, encoding)?;
            output_writer
                .write_all(&encoded_message)
                .map_err(|error| error.to_string())?;

            write_detached_signature(
                signature_writer,
                encrypted.detached_signature(),
                !matches!(encoding, DataEncoding::Unarmored),
            )?;
        } else {
            let encrypted = encryptor
                .encrypt_raw(message, encoding)
                .map_err(|error| error.to_string())?;
            output_writer
                .write_all(&encrypted)
                .map_err(|error| error.to_string())?;
        }

        Ok(())
    })
}

/// Validates a detached-signature request: a signature sink must be supplied and there must be
/// signing keys to produce the signature. Shared by [`pgp_encrypt`] and the streaming encrypt path
/// ([`encrypt_stream`]) so both fail with identical errors.
fn require_detached_signature_sink(
    signature_writer: ForeignWriter,
    have_signing_keys: bool,
) -> Result<(), String> {
    if signature_writer.is_null() {
        return Err("detached signature writer is required".to_string());
    }
    if !have_signing_keys {
        return Err("no signing keys provided".to_string());
    }
    Ok(())
}

/// Emits the detached signature to `writer`, armored or unarmored per `armored`. Shared by
/// [`pgp_encrypt`] and the streaming encrypt path ([`encrypt_stream`]) so the encoding policy has
/// exactly one home.
fn write_detached_signature(
    mut writer: ForeignWriter,
    detached: Option<&proton_rpgp::ExternalDetachedSignature<'_>>,
    armored: bool,
) -> Result<(), String> {
    let detached = detached.ok_or_else(|| "missing detached signature".to_string())?;
    let signature = if armored {
        detached.armored()
    } else {
        detached.unarmored()
    }
    .map_err(|error| error.to_string())?;
    writer
        .write_all(&signature)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
pub(crate) mod tests;
