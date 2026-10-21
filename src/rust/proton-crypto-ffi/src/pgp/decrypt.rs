use crate::pgp::keys::{
    PgpKey, owned_private_keys, owned_public_keys, private_keys_vec, public_keys_from_keys,
};
use std::io::Write;

use super::{
    DataEncoding, Decryptor, ForeignReader, FromId, InteropError, PlaintextResult, PrivateKey,
    Profile, PublicKey, ReaderHandle, ReaderJob, SessionKey, UnsafePtr, VerificationContext,
    catch_error, check_unix_time,
};
#[repr(C)]
pub(crate) struct DecryptionParameters {
    pub(crate) decryption_keys_len: usize,
    pub(crate) verification_keys_len: usize,
    pub(crate) password_len: usize,
    pub(crate) detached_sig_len: usize,
    pub(crate) has_session_key: bool,
    pub(crate) has_verification_context: bool,
    pub(crate) has_verification_time: bool,
    pub(crate) utf8: bool,
    pub(crate) detached_sig_is_encrypted: bool,
    pub(crate) detached_sig_is_armored: bool,
    pub(crate) decryption_keys: *const *const PgpKey,
    pub(crate) verification_keys: *const *const PgpKey,
    pub(crate) session_key: *const SessionKey,
    pub(crate) verification_context: *const VerificationContext,
    pub(crate) verification_time: u64,
    pub(crate) password: *const u8,
    pub(crate) detached_sig: *const u8,
}

#[derive(Clone, Copy)]
pub(crate) struct DecryptSettings {
    has_verification_time: bool,
    utf8: bool,
    detached_sig_is_encrypted: bool,
    detached_sig_is_armored: bool,
    verification_time: u64,
}

impl DecryptSettings {
    pub(crate) fn build_decryptor<'a>(
        &self,
        decryption_keys: impl IntoIterator<Item = &'a PrivateKey>,
        verification_keys: impl IntoIterator<Item = &'a PublicKey>,
        session_key: Option<&'a SessionKey>,
        verification_context: Option<&'a VerificationContext>,
        password: Option<&'a [u8]>,
        detached_signature: Option<&'a [u8]>,
    ) -> Decryptor<'a> {
        let mut decryptor = Decryptor::new(Profile::default())
            .allow_forwarding_decryption(true)
            .with_decryption_keys(decryption_keys)
            .with_verification_keys(verification_keys);
        if let Some(session_key) = session_key {
            decryptor = decryptor.with_session_key(session_key);
        }
        if let Some(password) = password {
            decryptor = decryptor.with_passphrase(password);
        }
        if let Some(verification_context) = verification_context {
            decryptor = decryptor.with_verification_context(verification_context);
        }
        if self.has_verification_time {
            decryptor = decryptor.at_date(check_unix_time(self.verification_time));
        }
        if self.utf8 {
            decryptor = decryptor.output_utf8();
        }
        if let Some(signature) = detached_signature {
            let encoding = if self.detached_sig_is_armored {
                DataEncoding::Armored
            } else {
                DataEncoding::Unarmored
            };
            let signature = if self.detached_sig_is_encrypted {
                proton_rpgp::ExternalDetachedSignature::new_encrypted(signature, encoding)
            } else {
                proton_rpgp::ExternalDetachedSignature::new_unencrypted(signature, encoding)
            };
            decryptor = decryptor.with_external_detached_signature(signature);
        }
        decryptor
    }
}

impl From<&DecryptionParameters> for DecryptSettings {
    fn from(params: &DecryptionParameters) -> Self {
        Self {
            has_verification_time: params.has_verification_time,
            utf8: params.utf8,
            detached_sig_is_encrypted: params.detached_sig_is_encrypted,
            detached_sig_is_armored: params.detached_sig_is_armored,
            verification_time: params.verification_time,
        }
    }
}

/// Decrypts (and verifies) an OpenPGP message, writing the plaintext into `result`.
///
/// `parameters` supplies decryption keys, verification keys, optional session key, verification
/// context, password, and detached signature; `encoding` selects the input encoding (0 armored,
/// 1 unarmored, other auto). Plaintext is written to the `ForeignWriter` inside `result` and the
/// verification-result handle is set on `result`.
///
/// # Safety
/// `parameters` must be a valid non-null pointer to an initialized `DecryptionParameters` whose
/// embedded key-handle arrays, `password`/`detached_sig` pointers, and session-key/verification-
/// context handles are valid; `body` must be valid for `body_len` bytes (or null when zero);
/// `result` must be a valid non-null, writable pointer to a `PlaintextResult` with a valid writer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_decrypt(
    parameters: *const DecryptionParameters,
    body: *const u8,
    body_len: usize,
    encoding: u8,
    result: *mut PlaintextResult,
) -> InteropError {
    catch_error(|| {
        let encoding = DataEncoding::from_id(encoding)?;
        let params = UnsafePtr::as_ref(parameters)?;
        let decryption_keys = private_keys_vec(params.decryption_keys, params.decryption_keys_len)?;
        let keys =
            UnsafePtr::get_handle_slice(params.verification_keys, params.verification_keys_len)?;
        let verification_keys = public_keys_from_keys(keys);
        let password = UnsafePtr::get_slice(params.password, params.password_len)?;
        let password = (!password.is_empty()).then_some(password);
        let session_key = UnsafePtr::maybe_ref(params.session_key, params.has_session_key)?;
        let verification_context =
            UnsafePtr::maybe_ref(params.verification_context, params.has_verification_context)?;
        let detached_signature =
            UnsafePtr::get_slice(params.detached_sig, params.detached_sig_len)?;
        let detached_signature = (!detached_signature.is_empty()).then_some(detached_signature);
        let body = UnsafePtr::get_slice(body, body_len)?;

        let decryptor = DecryptSettings::from(params).build_decryptor(
            decryption_keys,
            verification_keys,
            session_key,
            verification_context,
            password,
            detached_signature,
        );
        let verified = decryptor
            .decrypt(body, encoding)
            .map_err(|error| error.to_string())?;
        let result = UnsafePtr::ref_mut(result)?;
        result
            .plaintext_buffer
            .write_all(&verified.data)
            .map_err(|error| error.to_string())?;

        result.has_verification_result = true;
        result.verification_result = UnsafePtr::new_raw(verified.verification_result);

        Ok(())
    })
}

/// Starts streaming decryption (and verification), writing a reader handle into `out_reader`.
///
/// Opens an upstream decrypting reader over `input_reader` using the keys/options in `parameters`
/// (`encoding`: 0 armored, 1 unarmored, other auto). The message header is consumed synchronously
/// on the calling thread during this call, and each subsequent read on the handle pulls
/// ciphertext through `input_reader` on the reading thread. The verification result becomes available
///  once the stream is consumed. `input_reader` must remain valid until the reader handle is closed;
///  the caller owns the handle and MUST release it with the reader destroy fn.
///
/// # Safety
/// `parameters` must be a valid non-null pointer to an initialized `DecryptionParameters` whose
/// embedded key-handle arrays, `password`/`detached_sig` pointers, and session-key/verification-
/// context handles are valid; `input_reader` must be a valid host reader living until the returned
/// handle is destroyed; `out_reader` must be a valid non-null, writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_decrypt_stream(
    parameters: *const DecryptionParameters,
    input_reader: ForeignReader,
    encoding: u8,
    out_reader: *mut *mut ReaderHandle,
) -> InteropError {
    catch_error(|| {
        let encoding = DataEncoding::from_id(encoding)?;
        let params = UnsafePtr::as_ref(parameters)?;
        // Clone all host-borrowed inputs into the handle-owned job: the stream outlives this
        // call, and the host may free its key handles / buffers as soon as it returns.
        let password = UnsafePtr::get_slice(params.password, params.password_len)?;
        let detached_signature =
            UnsafePtr::get_slice(params.detached_sig, params.detached_sig_len)?;
        let job = ReaderJob {
            decryption_keys: owned_private_keys(
                params.decryption_keys,
                params.decryption_keys_len,
            )?,
            verification_keys: owned_public_keys(
                params.verification_keys,
                params.verification_keys_len,
            )?,
            session_key: UnsafePtr::maybe_ref(params.session_key, params.has_session_key)?.cloned(),
            verification_context: UnsafePtr::maybe_ref(
                params.verification_context,
                params.has_verification_context,
            )?
            .cloned(),
            password: (!password.is_empty()).then(|| password.to_vec()),
            detached_signature: (!detached_signature.is_empty())
                .then(|| detached_signature.to_vec()),
        };
        let settings = DecryptSettings::from(params);

        let handle = ReaderHandle::try_new(job, move |job| {
            let decryptor = settings.build_decryptor(
                job.decryption_keys.iter(),
                job.verification_keys.iter(),
                job.session_key.as_ref(),
                job.verification_context.as_ref(),
                job.password.as_deref(),
                job.detached_signature.as_deref(),
            );
            decryptor
                .decrypt_stream(input_reader, encoding)
                .map_err(|error| error.to_string())
        })?;

        *UnsafePtr::ref_mut(out_reader)? = UnsafePtr::new_raw(handle);
        Ok(())
    })
}

/// Decrypts OpenPGP key packets into a session key, writing the handle into `out_session_key`.
///
/// Decryption keys, optional session key, verification context, and password are taken from
/// `parameters` (no detached signature is used). The caller owns the returned session-key handle
/// and MUST release it with the session-key destroy fn.
///
/// # Safety
/// `parameters` must be a valid non-null pointer to an initialized `DecryptionParameters` whose
/// embedded key-handle arrays, `password` pointer, and session-key/verification-context handles are
/// valid; `key_packets` must be valid for `key_packets_len` bytes (or null when zero);
/// `out_session_key` must be a valid non-null, writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_decrypt_session_key(
    parameters: *const DecryptionParameters,
    key_packets: *const u8,
    key_packets_len: usize,
    out_session_key: *mut *mut SessionKey,
) -> InteropError {
    catch_error(|| {
        let params = UnsafePtr::as_ref(parameters)?;
        let decryption_keys = private_keys_vec(params.decryption_keys, params.decryption_keys_len)?;
        let keys =
            UnsafePtr::get_handle_slice(params.verification_keys, params.verification_keys_len)?;
        let verification_keys = public_keys_from_keys(keys);
        let password = UnsafePtr::get_slice(params.password, params.password_len)?;
        let password = (!password.is_empty()).then_some(password);
        let session_key = UnsafePtr::maybe_ref(params.session_key, params.has_session_key)?;
        let verification_context =
            UnsafePtr::maybe_ref(params.verification_context, params.has_verification_context)?;
        let decryptor = DecryptSettings::from(params).build_decryptor(
            decryption_keys,
            verification_keys,
            session_key,
            verification_context,
            password,
            None,
        );
        let session_key = UnsafePtr::get_slice(key_packets, key_packets_len)?;
        let session_key = decryptor
            .decrypt_session_key(session_key)
            .map_err(|error| error.to_string())?;

        *UnsafePtr::ref_mut(out_session_key)? = UnsafePtr::new_raw(session_key);
        Ok(())
    })
}

#[cfg(test)]
pub(crate) mod tests;
