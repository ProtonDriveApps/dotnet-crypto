use proton_rpgp::{HAZARD_AEAD_PROFILE, UnixTime, pgp::types::KeyId};
use std::io::Write;

use super::{
    AsPublicKeyRef, DEFAULT_PROFILE, DataEncoding, ForeignWriter, FromId, InteropError,
    KeyGenerationType, KeyGenerator, KeyLock, LockedPrivateKey, PrivateKey, Profile, PublicKey,
    SessionKey, SymmetricKeyAlgorithm, ToId, UnsafePtr, catch_error, malloc_bytes,
};

#[repr(C)]
pub(crate) struct KeyGenerationParameters {
    profile: u8,
    has_generation_time: bool,
    has_user_id: bool,
    name: *const u8,
    name_len: usize,
    email: *const u8,
    email_len: usize,
    generation_time: u64,
    algorithm: u8,
}
#[derive(Clone)]
pub enum PgpKey {
    Public(PublicKey),
    Private(PrivateKey),
    LockedPrivate(LockedPrivateKey),
}

impl PgpKey {
    pub(crate) fn public_ref(&self) -> &PublicKey {
        match self {
            Self::Public(key) => key,
            Self::Private(key) => key.as_public_key(),
            Self::LockedPrivate(key) => key.as_public_key(),
        }
    }

    pub(crate) fn private_ref(&self) -> Result<&PrivateKey, String> {
        match self {
            Self::Private(key) => Ok(key),
            Self::LockedPrivate(_) => Err("key is locked".to_string()),
            Self::Public(_) => Err("private key required".to_string()),
        }
    }

    fn lock(&self, password: &[u8]) -> Result<LockedPrivateKey, String> {
        self.private_ref()?
            .lock(&DEFAULT_PROFILE, password)
            .map_err(|error| error.to_string())
    }

    fn unlock(&self, password: &[u8]) -> Result<PrivateKey, String> {
        match self {
            Self::Private(_) => Err("key is not locked".to_string()),
            Self::LockedPrivate(key) => key
                .unlock(password, KeyLock::Expected)
                .map_err(|error| error.to_string()),
            Self::Public(_) => Err("private key required".to_string()),
        }
    }

    fn export_bytes(&self, encoding: DataEncoding) -> Result<Vec<u8>, String> {
        match self {
            Self::Public(key) => key.export(encoding).map_err(|error| error.to_string()),
            Self::Private(key) => key
                .export_unlocked(encoding)
                .map_err(|error| error.to_string()),
            Self::LockedPrivate(key) => key.export(encoding).map_err(|error| error.to_string()),
        }
    }
}

/// Converts an OpenPGP key id to its big-endian `u64` representation (the conventional key id).
/// Used wherever a key id crosses the FFI boundary (key handles, message key ids, verification
/// results) so the host sees a single, consistent numeric form.
pub(crate) fn key_id_as_u64(key_id: &KeyId) -> Result<u64, String> {
    key_id
        .as_ref()
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|error| error.to_string())
}

/// Maps a slice of borrowed key handles to their public keys (every key has one, so infallible).
pub(crate) fn public_keys_from_keys<'a>(
    keys: &'a [&'a PgpKey],
) -> impl Iterator<Item = &'a PublicKey> {
    keys.iter().map(|key| key.public_ref())
}

/// Fails if any handle does not hold an unlocked private key.
pub(crate) fn private_keys_from_keys<'a>(
    keys: &'a [&'a PgpKey],
) -> impl Iterator<Item = Result<&'a PrivateKey, String>> {
    keys.iter().map(|key| key.private_ref())
}

/// Collects the private keys behind a host key-handle array; fails on locked/public handles.
///
/// # Safety
/// `keys` must point to `len` consecutive live key handles (see [`UnsafePtr::get_handle_slice`]).
pub(crate) fn private_keys_vec(
    keys: *const *const PgpKey,
    len: usize,
) -> Result<Vec<&'static PrivateKey>, String> {
    private_keys_from_keys(UnsafePtr::get_handle_slice(keys, len)?).collect()
}

/// Clones the private keys behind a host key-handle array into owned values, so they can be moved
/// into a worker thread that outlives the caller's key handles. Owned counterpart of
/// [`private_keys_vec`]; fails on locked/public handles.
///
/// # Safety
/// `keys` must point to `len` consecutive live key handles (see [`UnsafePtr::get_handle_slice`]).
pub(crate) fn owned_private_keys(
    keys: *const *const PgpKey,
    len: usize,
) -> Result<Vec<PrivateKey>, String> {
    private_keys_from_keys(UnsafePtr::get_handle_slice(keys, len)?)
        .map(|key| key.cloned())
        .collect()
}

/// Clones the public keys behind a host key-handle array into owned values (every key has one).
/// Owned counterpart of [`public_keys_from_keys`].
///
/// # Safety
/// `keys` must point to `len` consecutive live key handles (see [`UnsafePtr::get_handle_slice`]).
pub(crate) fn owned_public_keys(
    keys: *const *const PgpKey,
    len: usize,
) -> Result<Vec<PublicKey>, String> {
    let slice = UnsafePtr::get_handle_slice(keys, len)?;
    Ok(public_keys_from_keys(slice).cloned().collect())
}

impl FromId for SymmetricKeyAlgorithm {
    type Output = Result<SymmetricKeyAlgorithm, String>;

    fn from_id(value: u8) -> Self::Output {
        match value {
            2 => Ok(SymmetricKeyAlgorithm::TripleDES),
            3 => Ok(SymmetricKeyAlgorithm::CAST5),
            7 => Ok(SymmetricKeyAlgorithm::AES128),
            8 => Ok(SymmetricKeyAlgorithm::AES192),
            9 => Ok(SymmetricKeyAlgorithm::AES256),
            _ => Err("unsupported cipher".to_string()),
        }
    }
}

impl ToId for SymmetricKeyAlgorithm {
    type Input = SymmetricKeyAlgorithm;

    fn to_id(value: Self::Input) -> Result<u8, String> {
        match value {
            SymmetricKeyAlgorithm::TripleDES => Ok(2),
            SymmetricKeyAlgorithm::CAST5 => Ok(3),
            SymmetricKeyAlgorithm::AES128 => Ok(7),
            SymmetricKeyAlgorithm::AES192 => Ok(8),
            SymmetricKeyAlgorithm::AES256 => Ok(9),
            _ => Err("unsupported cipher".to_string()),
        }
    }
}

impl FromId for KeyGenerationType {
    type Output = Result<KeyGenerationType, String>;

    fn from_id(value: u8) -> Result<KeyGenerationType, String> {
        match value {
            0 | 2 => Ok(KeyGenerationType::ECC),
            1 => Ok(KeyGenerationType::RSA),
            _ => Err("unsupported key generation algorithm".to_string()),
        }
    }
}

/// Imports an OpenPGP public key and returns an opaque key handle.
///
/// `key`/`key_len` is the serialized key; `encoding` selects the input format (0 = armored,
/// 1 = unarmored, other = auto-detect). On success `out_public_key` receives a handle that must
/// be released with `pgp_key_destroy`.
///
/// # Safety
/// `key` must be valid for `key_len` bytes (or null when `key_len == 0`) and `out_public_key`
/// must be a non-null, writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_public_key_import(
    key: *const u8,
    key_len: usize,
    encoding: u8,
    out_public_key: *mut *mut PgpKey,
) -> InteropError {
    catch_error(|| {
        let encoding = DataEncoding::from_id(encoding)?;
        let key = UnsafePtr::get_slice(key, key_len)?;
        let public_key = PublicKey::import(key, encoding).map_err(|error| error.to_string())?;

        *UnsafePtr::ref_mut(out_public_key)? = UnsafePtr::new_raw(PgpKey::Public(public_key));
        Ok(())
    })
}

/// Imports a locked OpenPGP private key and returns an opaque key handle.
///
/// `key`/`key_len` is the serialized key; `encoding` selects the input format (0 = armored,
/// 1 = unarmored, other = auto-detect). The key is kept locked (no passphrase applied); on success
/// `out_private_key` receives a handle that must be released with `pgp_key_destroy`.
///
/// # Safety
/// `key` must be valid for `key_len` bytes (or null when `key_len == 0`) and `out_private_key`
/// must be a non-null, writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_locked_private_key_import(
    key: *const u8,
    key_len: usize,
    encoding: u8,
    out_private_key: *mut *mut PgpKey,
) -> InteropError {
    catch_error(|| {
        let encoding = DataEncoding::from_id(encoding)?;
        let key = UnsafePtr::get_slice(key, key_len)?;
        // The key is assumed to not be locked, so there is no passphrase required.
        let imported = PgpKey::LockedPrivate(
            LockedPrivateKey::import(key, encoding).map_err(|error| error.to_string())?,
        );

        *UnsafePtr::ref_mut(out_private_key)? = UnsafePtr::new_raw(imported);
        Ok(())
    })
}

/// Imports an unlocked OpenPGP private key and returns an opaque key handle.
///
/// `key`/`key_len` is the serialized key; `encoding` selects the input format (0 = armored,
/// 1 = unarmored, other = auto-detect). The key is imported unlocked (no passphrase required); on
/// success `out_private_key` receives a handle that must be released with `pgp_key_destroy`.
///
/// # Safety
/// `key` must be valid for `key_len` bytes (or null when `key_len == 0`) and `out_private_key`
/// must be a non-null, writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_private_key_import(
    key: *const u8,
    key_len: usize,
    encoding: u8,
    out_private_key: *mut *mut PgpKey,
) -> InteropError {
    catch_error(|| {
        let encoding = DataEncoding::from_id(encoding)?;
        let key = UnsafePtr::get_slice(key, key_len)?;
        // The key is assumed to not be locked, so there is no passphrase required.
        let imported = PgpKey::Private(
            PrivateKey::import_unlocked(key, encoding).map_err(|error| error.to_string())?,
        );

        *UnsafePtr::ref_mut(out_private_key)? = UnsafePtr::new_raw(imported);
        Ok(())
    })
}

/// Imports an OpenPGP private key and unlocks it with the given passphrase, returning a handle.
///
/// `key`/`key_len` is the serialized key; `encoding` selects the input format (0 = armored,
/// 1 = unarmored, other = auto-detect); `passphrase`/`passphrase_len` decrypts the secret material.
/// On success `out_private_key` receives an unlocked-key handle that must be released with
/// `pgp_key_destroy`.
///
/// # Safety
/// `key` must be valid for `key_len` bytes and `passphrase` for `passphrase_len` bytes (each may be
/// null only when its length is 0); `out_private_key` must be a non-null, writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_private_key_import_unlock(
    key: *const u8,
    key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    encoding: u8,
    out_private_key: *mut *mut PgpKey,
) -> InteropError {
    catch_error(|| {
        let encoding = DataEncoding::from_id(encoding)?;
        let key = UnsafePtr::get_slice(key, key_len)?;
        let passphrase = UnsafePtr::get_slice(passphrase, passphrase_len)?;
        let imported = PgpKey::Private(
            PrivateKey::import(key, passphrase, encoding).map_err(|error| error.to_string())?,
        );

        *UnsafePtr::ref_mut(out_private_key)? = UnsafePtr::new_raw(imported);
        Ok(())
    })
}

/// Derives the public key from a key handle and returns it as a new opaque public-key handle.
///
/// `ptr` is a key handle (public, locked, or unlocked private). On success `out_public_key`
/// receives a freshly cloned public-key handle that must be released with `pgp_key_destroy`;
/// `ptr` is unaffected.
///
/// # Safety
/// `ptr` must be a live key handle and `out_public_key` must be a non-null, writable
/// handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_private_key_get_public_key(
    ptr: *const PgpKey,
    out_public_key: *mut *mut PgpKey,
) -> InteropError {
    catch_error(|| {
        // Validate the out-pointer before allocating, so a null `out_public_key` is a clean
        // error (not a null write) and never leaks the freshly boxed handle.
        let out = UnsafePtr::ref_mut(out_public_key)?;
        let public_key = UnsafePtr::as_ref(ptr)?.public_ref();

        *out = UnsafePtr::new_raw(PgpKey::Public(public_key.to_owned()));
        Ok(())
    })
}

/// Serializes a key handle and writes the bytes to the supplied foreign writer.
///
/// `ptr` is the key to export; `force_public` exports only the public part even for a private key;
/// `armored` selects ASCII-armored (true) versus binary (false) output. The serialized bytes are
/// streamed to `output_writer`.
///
/// # Safety
/// `ptr` must be a live key handle and `output_writer` must be a valid `ForeignWriter`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_key_export(
    ptr: *const PgpKey,
    force_public: bool,
    armored: bool,
    mut output_writer: ForeignWriter,
) -> InteropError {
    let encoding = if armored {
        DataEncoding::Armored
    } else {
        DataEncoding::Unarmored
    };

    catch_error(|| {
        let key = UnsafePtr::as_ref(ptr)?;
        let bytes = if force_public {
            key.public_ref()
                .export(encoding)
                .map_err(|error| error.to_string())?
        } else {
            key.export_bytes(encoding)?
        };

        output_writer
            .write_all(&bytes)
            .map_err(|error| error.to_string())
    })
}

/// Locks (encrypts) an unlocked private key with a passphrase, returning a new locked-key handle.
///
/// `unlocked_key` is the source private key; `passphrase`/`passphrase_len` is the encrypting
/// passphrase. On success `out_locked_private_key` receives a new locked-key handle that must be
/// released with `pgp_key_destroy`; `unlocked_key` is unaffected. Returns failure if `passphrase`
/// or `out_locked_private_key` is null.
///
/// # Safety
/// `unlocked_key` must be a live key handle; `passphrase` must be valid for `passphrase_len` bytes;
/// `out_locked_private_key` must be a writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_key_lock(
    unlocked_key: *const PgpKey,
    passphrase: *const u8,
    passphrase_len: usize,
    out_locked_private_key: *mut *mut PgpKey,
) -> InteropError {
    catch_error(|| {
        let password = UnsafePtr::get_slice(passphrase, passphrase_len)?;
        let locked_private_key = UnsafePtr::as_ref(unlocked_key)?.lock(password)?;
        *UnsafePtr::ref_mut(out_locked_private_key)? =
            UnsafePtr::new_raw(PgpKey::LockedPrivate(locked_private_key));
        Ok(())
    })
}

/// Unlocks (decrypts) a locked private key with a passphrase, returning a new unlocked-key handle.
///
/// `locked_key` is the source locked private key; `passphrase`/`passphrase_len` decrypts the secret
/// material. On success `out_unlocked_private_key` receives a new unlocked-key handle that must be
/// released with `pgp_key_destroy`; `locked_key` is unaffected. Returns failure if `passphrase` or
/// `out_unlocked_private_key` is null.
///
/// # Safety
/// `locked_key` must be a live key handle; `passphrase` must be valid for `passphrase_len` bytes;
/// `out_unlocked_private_key` must be a writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_key_unlock(
    locked_key: *const PgpKey,
    passphrase: *const u8,
    passphrase_len: usize,
    out_unlocked_private_key: *mut *mut PgpKey,
) -> InteropError {
    catch_error(|| {
        let password = UnsafePtr::get_slice(passphrase, passphrase_len)?;
        let unlocked_private_key = UnsafePtr::as_ref(locked_key)?.unlock(password)?;
        *UnsafePtr::ref_mut(out_unlocked_private_key)? =
            UnsafePtr::new_raw(PgpKey::Private(unlocked_private_key));
        Ok(())
    })
}

/// Frees a key handle created by the key import, derivation, lock/unlock, or generation functions.
///
/// # Safety
/// `ptr` must be a live key handle and must not be used again after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_key_destroy(ptr: *mut PgpKey) {
    UnsafePtr::drop_raw(ptr);
}

/// Builds a session key from an existing key token and cipher id, returning an opaque handle.
///
/// `token`/`token_len` is the raw session-key bytes; `cipher` is the OpenPGP symmetric-key algorithm
/// id (2 = TripleDES, 3 = CAST5, 7 = AES128, 8 = AES192, 9 = AES256; other values error). On success
/// `out_session_key` receives a handle that must be released with `pgp_session_key_destroy`.
///
/// # Safety
/// `token` must be valid for `token_len` bytes (or null when `token_len == 0`) and `out_session_key`
/// must be a non-null, writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_new_session_key_from_token(
    token: *const u8,
    token_len: usize,
    cipher: u8,
    out_session_key: *mut *mut SessionKey,
) -> InteropError {
    catch_error(|| {
        *UnsafePtr::ref_mut(out_session_key)? = UnsafePtr::new_raw(SessionKey::new_for_seipdv1(
            UnsafePtr::get_slice(token, token_len)?,
            SymmetricKeyAlgorithm::from_id(cipher)?,
        ));
        Ok(())
    })
}

/// Builds a SEIPDv2/AEAD (v6) session key from an existing key token, returning an opaque handle.
///
/// `token`/`token_len` is the raw session-key bytes. The `cipher` argument is accepted for ABI
/// parity but ignored: the key is constructed for SEIPDv2 regardless. On success `out_session_key`
/// receives a handle that must be released with `pgp_session_key_destroy`.
///
/// # Safety
/// `token` must be valid for `token_len` bytes (or null when `token_len == 0`) and `out_session_key`
/// must be a non-null, writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_new_session_key_from_token_aead(
    token: *const u8,
    token_len: usize,
    _cipher: u8,
    out_session_key: *mut *mut SessionKey,
) -> InteropError {
    catch_error(|| {
        *UnsafePtr::ref_mut(out_session_key)? = UnsafePtr::new_raw(SessionKey::new_for_seipdv2(
            UnsafePtr::get_slice(token, token_len)?,
        ));
        Ok(())
    })
}

/// Generates a fresh random SEIPDv1 session key for the given cipher, returning an opaque handle.
///
/// `cipher` is the OpenPGP symmetric-key algorithm id (2 = TripleDES, 3 = CAST5, 7 = AES128,
/// 8 = AES192, 9 = AES256; other values error). On success `out_session_key` receives a handle that
/// must be released with `pgp_session_key_destroy`.
///
/// # Safety
/// `out_session_key` must be a non-null, writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_generate_session_key(
    cipher: u8,
    out_session_key: *mut *mut SessionKey,
) -> InteropError {
    catch_error(|| {
        *UnsafePtr::ref_mut(out_session_key)? =
            UnsafePtr::new_raw(SessionKey::generate_for_seipdv1(
                SymmetricKeyAlgorithm::from_id(cipher)?,
                &proton_rpgp::DEFAULT_PROFILE,
            ));
        Ok(())
    })
}

/// Generates a fresh random SEIPDv2/AEAD (v6) session key for the given cipher, returning a handle.
///
/// `cipher` is the OpenPGP symmetric-key algorithm id (2 = TripleDES, 3 = CAST5, 7 = AES128,
/// 8 = AES192, 9 = AES256; other values error). The key is generated for SEIPDv2 using a v6 profile.
/// On success `out_session_key` receives a handle that must be released with
/// `pgp_session_key_destroy`.
///
/// # Safety
/// `out_session_key` must be a non-null, writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_generate_session_key_aead(
    cipher: u8,
    out_session_key: *mut *mut SessionKey,
) -> InteropError {
    catch_error(|| {
        *UnsafePtr::ref_mut(out_session_key)? =
            UnsafePtr::new_raw(SessionKey::generate_for_seipdv2(
                SymmetricKeyAlgorithm::from_id(cipher)?,
                &HAZARD_AEAD_PROFILE,
            ));
        Ok(())
    })
}

/// Exports a session key's raw token bytes into a freshly allocated C-heap buffer.
///
/// `ptr` is the session key to export. On success `out_token` receives a pointer to a C-heap buffer
/// and `out_token_len` its length; the caller MUST free the buffer with `interop_memory_free`.
/// Returns failure if `out_token` or `out_token_len` is null.
///
/// # Safety
/// `ptr` must be a live session-key handle; `out_token` must be a writable `*mut *mut u8` and
/// `out_token_len` a writable `*mut usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_session_key_export_token(
    ptr: *const SessionKey,
    out_token: *mut *mut u8,
    out_token_len: *mut usize,
) -> InteropError {
    catch_error(|| {
        let token = UnsafePtr::as_ref(ptr)?.export_bytes();
        *UnsafePtr::ref_mut(out_token)? = malloc_bytes(token.as_ref())?;
        *UnsafePtr::ref_mut(out_token_len)? = token.as_ref().len();
        Ok(())
    })
}

/// Writes the session key's OpenPGP symmetric-key algorithm id into `*out_cipher`.
///
/// `ptr` is the session key. The mapped cipher id is one of 2 = TripleDES, 3 = CAST5, 7 = AES128,
/// 8 = AES192, 9 = AES256; if the key has no explicit algorithm, one is inferred from a v6 profile's
/// fallback ciphersuite for the key length. Returns failure if no algorithm can be determined or it
/// is unsupported.
///
/// # Safety
/// `ptr` must be a live session-key handle and `out_cipher` must be a non-null, writable `*mut u8`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_session_key_get_algorithm(
    ptr: *const SessionKey,
    out_cipher: *mut u8,
) -> InteropError {
    catch_error(|| {
        let session_key = UnsafePtr::as_ref(ptr)?;
        let algorithm = session_key
            .algorithm()
            .or_else(|| {
                HAZARD_AEAD_PROFILE
                    .fallback_ciphersuite_for_key_length(session_key.export_bytes().as_ref().len())
                    .map(|value| value.0)
            })
            .ok_or_else(|| "missing session key algorithm".to_string())?;

        let cipher = SymmetricKeyAlgorithm::to_id(algorithm)?;

        *UnsafePtr::ref_mut(out_cipher)? = cipher;
        Ok(())
    })
}

/// Reports whether the session key is an AEAD (SEIPDv2) key.
///
/// `ptr` is the session key; the result (true when the key has no explicit symmetric algorithm) is
/// written to `out_is_aead`. Returns failure if `out_is_aead` is null.
///
/// # Safety
/// `ptr` must be a live session-key handle and `out_is_aead` must be a writable `*mut bool`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_session_key_is_aead(
    ptr: *const SessionKey,
    out_is_aead: *mut bool,
) -> InteropError {
    catch_error(|| {
        *UnsafePtr::ref_mut(out_is_aead)? = UnsafePtr::as_ref(ptr)?.is_seipdv2_aead();
        Ok(())
    })
}

/// Frees a session-key handle created by the session-key construction or generation functions.
///
/// # Safety
/// `ptr` must be a live session-key handle and must not be used again after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_session_key_destroy(ptr: *mut SessionKey) {
    UnsafePtr::drop_raw(ptr);
}
/// Generates a new OpenPGP private key from the supplied parameters, returning an opaque handle.
///
/// `parameters` points to a `#[repr(C)]` `KeyGenerationParameters` selecting the profile, key
/// algorithm, optional user id (name/email, when `has_user_id`), and optional generation time (when
/// `has_generation_time`). On success `out_private_key` receives an unlocked private-key handle that
/// must be released with `pgp_key_destroy`.
///
/// # Safety
/// `parameters` must be a non-null pointer to a fully initialized `KeyGenerationParameters` whose
/// embedded name/email pointers (when `has_user_id`) are valid UTF-8 slices for their lengths;
/// `out_private_key` must be a non-null, writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_generate_key(
    parameters: *const KeyGenerationParameters,
    out_private_key: *mut *mut PgpKey,
) -> InteropError {
    catch_error(|| {
        let params = UnsafePtr::as_ref(parameters)?;
        let profile = Profile::from_id(params.profile);
        let mut generator =
            KeyGenerator::new(profile).with_key_type(KeyGenerationType::from_id(params.algorithm)?);
        if params.has_user_id {
            generator = generator.with_user_id(
                UnsafePtr::get_str(params.name, params.name_len)?,
                UnsafePtr::get_str(params.email, params.email_len)?,
            );
        }
        if params.has_generation_time {
            generator = generator.at_date(UnixTime::new(params.generation_time));
        }
        let key = generator.generate().map_err(|error| error.to_string())?;

        *UnsafePtr::ref_mut(out_private_key)? = UnsafePtr::new_raw(PgpKey::Private(key));
        Ok(())
    })
}

#[cfg(test)]
mod tests;
