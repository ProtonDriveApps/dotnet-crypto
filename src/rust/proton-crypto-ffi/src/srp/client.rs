use super::{
    BASE64_STANDARD, ClientCreationParameters, ClientHandshakeBuffers, DataEncoding, Engine,
    InteropError, PgpKey, PublicKey, SRPAuth, SrpAuth, SrpClientHandshake, SrpHashVersion,
    UnsafePtr, catch_error, copy_to_host_buffer, mailbox_password_hash, verification_key_from_ptr,
};
use proton_srp::RPGPVerifier;
/// Returns a handle to the embedded Proton SRP modulus-verification public key.
///
/// Writes a fresh public-key handle into `out_key` (release with `pgp_key_destroy`).
///
/// # Safety
/// `out_key` must be non-null and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn srp_get_modulus_verification_key(
    out_key: *mut *mut PgpKey,
) -> InteropError {
    catch_error(|| {
        let armored = include_str!("../../resources/server_public_key.asc");
        let key = PublicKey::import(armored.as_bytes(), DataEncoding::Armored)
            .map_err(|error| error.to_string())?;

        *UnsafePtr::ref_mut(out_key)? = UnsafePtr::new_raw(PgpKey::Public(key));
        Ok(())
    })
}

/// Creates an SRP client auth handle from the username, password, salt, and signed modulus.
///
/// `parameters` supplies the client creation fields; the resulting auth handle is written into
/// `out_auth` (release with `srp_auth_destroy`). `verification_key` is validated for ABI
/// compatibility but does not influence verification: the modulus signature is checked against
/// proton-srp's embedded server key during `srp_auth_derive_verifier` / `srp_client_handshake_compute`.
///
/// # Safety
/// `parameters` must be a non-null pointer to an initialized `ClientCreationParameters` whose
/// byte/string fields are valid for their lengths; `verification_key` must be a live key handle;
/// `out_auth` must be non-null and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn srp_auth_create(
    parameters: *const ClientCreationParameters,
    verification_key: *const PgpKey,
    out_auth: *mut *mut SrpAuth,
) -> InteropError {
    catch_error(|| {
        let params = UnsafePtr::as_ref(parameters)?;
        // Validate the supplied key handle to preserve the FFI contract, but the modulus is
        // verified against proton-srp's embedded server key (see `FfiModulusVerifier`).
        let _ = verification_key_from_ptr(verification_key)?;

        let salt = UnsafePtr::get_slice(params.salt, params.salt_len)?;

        let auth = SrpAuth {
            username: UnsafePtr::get_string(params.username, params.username_len)?,
            password: UnsafePtr::get_string(params.password, params.password_len)?.into(),
            salt_b64: BASE64_STANDARD.encode(salt),
            signed_modulus: UnsafePtr::get_string(
                params.signed_modulus,
                params.signed_modulus_len,
            )?,
        };

        *UnsafePtr::ref_mut(out_auth)? = UnsafePtr::new_raw(auth);
        Ok(())
    })
}

/// Derives the SRP verifier for the auth handle, verifying the modulus against proton-srp's embedded key.
///
/// The verifier bytes are written into the caller-provided `(verifier_buffer, verifier_buffer_len)`,
/// failing if the buffer is too small. `_bit_length` is currently unused.
///
/// # Safety
/// `ptr` must be a live auth handle from `srp_auth_create`; `verifier_buffer` must be non-null and
/// writable for `verifier_buffer_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn srp_auth_derive_verifier(
    ptr: *const SrpAuth,
    verifier_buffer: *mut u8,
    verifier_buffer_len: usize,
    _bit_length: i32,
) -> InteropError {
    catch_error(|| {
        let auth = UnsafePtr::as_ref(ptr)?;
        let verifier = RPGPVerifier::default();
        let generated = SRPAuth::generate_verifier(
            &verifier,
            &auth.password,
            Some(&auth.salt_b64),
            &auth.signed_modulus,
        )
        .map_err(|error| error.to_string())?;

        copy_to_host_buffer(
            &generated.verifier,
            verifier_buffer,
            verifier_buffer_len,
            "verifier",
        )?;
        Ok(())
    })
}

/// Computes the SRP client proof and ephemeral from the server ephemeral, verifying the modulus.
///
/// `server_ephemeral`/`server_ephemeral_len` is the server's ephemeral value; the resulting client
/// proof and ephemeral are written into the buffers in `client_handshake_buffers` (failing if either
/// buffer is too small), and a handle for later proof verification is written into
/// `out_client_exchange` (release with `srp_client_handshake_destroy`). `_bit_length` is currently unused.
///
/// # Safety
/// `ptr` must be a live auth handle from `srp_auth_create`; `server_ephemeral` must be valid for its
/// length or null when zero; `client_handshake_buffers` must point to an initialized struct whose
/// buffers are writable for their lengths; `out_client_exchange` must be non-null and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn srp_client_handshake_compute(
    ptr: *const SrpAuth,
    server_ephemeral: *const u8,
    server_ephemeral_len: usize,
    client_handshake_buffers: *mut ClientHandshakeBuffers,
    _bit_length: i32,
    out_client_exchange: *mut *mut SrpClientHandshake,
) -> InteropError {
    catch_error(|| {
        let auth = UnsafePtr::as_ref(ptr)?;
        let verifier = RPGPVerifier::default();
        let server_ephemeral = UnsafePtr::get_slice(server_ephemeral, server_ephemeral_len)?;
        let server_ephemeral_b64 = BASE64_STANDARD.encode(server_ephemeral);
        let auth = SRPAuth::new(
            &verifier,
            Some(&auth.username),
            &auth.password,
            SrpHashVersion::V4,
            &auth.salt_b64,
            &auth.signed_modulus,
            &server_ephemeral_b64,
        )
        .map_err(|error| error.to_string())?;
        let proof = auth.generate_proofs().map_err(|error| error.to_string())?;
        let buffers = UnsafePtr::as_ref(client_handshake_buffers)?;
        copy_to_host_buffer(
            &proof.client_proof,
            buffers.proof_buffer,
            buffers.proof_buffer_len,
            "client handshake",
        )?;
        copy_to_host_buffer(
            &proof.client_ephemeral,
            buffers.ephemeral_buffer,
            buffers.ephemeral_buffer_len,
            "client handshake",
        )?;

        *UnsafePtr::ref_mut(out_client_exchange)? =
            UnsafePtr::new_raw(SrpClientHandshake { proof });
        Ok(())
    })
}

/// Verifies the server proof against the client handshake's expected value.
///
/// `server_proof`/`server_proof_len` is the server's proof; the boolean comparison result is written
/// into `out_is_valid`.
///
/// # Safety
/// `ptr` must be a live client-handshake handle from `srp_client_handshake_compute`; `server_proof`
/// must be valid for its length or null when zero; `out_is_valid` must be non-null and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn srp_client_handshake_verify_proof(
    ptr: *const SrpClientHandshake,
    server_proof: *const u8,
    server_proof_len: usize,
    out_is_valid: *mut bool,
) -> InteropError {
    catch_error(|| {
        *UnsafePtr::ref_mut(out_is_valid)? = UnsafePtr::as_ref(ptr)?
            .proof
            .compare_server_proof(UnsafePtr::get_slice(server_proof, server_proof_len)?);
        Ok(())
    })
}

/// Frees an SRP auth handle created by `srp_auth_create`.
///
/// # Safety
/// `ptr` must be a live auth handle from `srp_auth_create` and must not be reused afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn srp_auth_destroy(ptr: *mut SrpAuth) {
    UnsafePtr::drop_raw(ptr);
}

/// Frees an SRP client-handshake handle created by `srp_client_handshake_compute`.
///
/// # Safety
/// `ptr` must be a live client-handshake handle from `srp_client_handshake_compute` and must not be
/// reused afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn srp_client_handshake_destroy(ptr: *mut SrpClientHandshake) {
    UnsafePtr::drop_raw(ptr);
}

/// Computes the mailbox password hash from the password and salt.
///
/// `(password, password_len)` is the UTF-8 password and `(salt, salt_len)` the salt; the resulting
/// hash is written into `(digest_buffer, digest_buffer_len)`, failing if the buffer is too small.
///
/// # Safety
/// `password` and `salt` must each be valid for their lengths or null when zero; `digest_buffer` must
/// be non-null and writable for `digest_buffer_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hash_password(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    digest_buffer: *mut u8,
    digest_buffer_len: usize,
) -> InteropError {
    catch_error(|| {
        let password = std::str::from_utf8(UnsafePtr::get_slice(password, password_len)?)
            .map_err(|error| error.to_string())?;
        let salt = UnsafePtr::get_slice(salt, salt_len)?;
        let hash = mailbox_password_hash(password, salt).map_err(|error| error.to_string())?;

        copy_to_host_buffer(hash.as_bytes(), digest_buffer, digest_buffer_len, "digest")?;
        Ok(())
    })
}

#[cfg(test)]
mod tests;
