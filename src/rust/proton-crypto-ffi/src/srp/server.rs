use super::{
    InteropError, Mutex, RawSRPModulus, ServerClientProof, ServerClientVerifier,
    ServerCreationParameters, ServerInteraction, ServerInteractionState, SrpServer, UnsafePtr,
    catch_error, copy_to_host_buffer,
};

/// Converts a host-supplied `i32` length to `usize`, rejecting negative values.
fn checked_len(len: i32, what: &str) -> Result<usize, String> {
    usize::try_from(len).map_err(|_| format!("{what} is negative"))
}
/// Generates the SRP server handshake challenge from the modulus and verifier.
///
/// `parameters` supplies the modulus and verifier. If `(secret, secret_len)` is non-null and
/// positive, the server interaction is restored from that ephemeral secret; otherwise a fresh
/// interaction is created. The server ephemeral challenge is written into
/// `(ephemeral_buffer, ephemeral_buffer_len)` (failing if too small), and a server handle is written
/// into `out_server_handshake` (release with `srp_server_destroy`).
///
/// # Safety
/// `parameters` must be a non-null pointer to an initialized `ServerCreationParameters` whose byte
/// fields are valid for their lengths; `secret` must be valid for `secret_len` bytes or null;
/// `ephemeral_buffer` must be non-null and writable for `ephemeral_buffer_len` bytes;
/// `out_server_handshake` must be non-null and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn srp_server_generate_handshake(
    parameters: *const ServerCreationParameters,
    secret: *const u8,
    secret_len: i32,
    ephemeral_buffer: *mut u8,
    ephemeral_buffer_len: usize,
    out_server_handshake: *mut *mut SrpServer,
) -> InteropError {
    catch_error(|| {
        let params = UnsafePtr::as_ref(parameters)?;
        let modulus = UnsafePtr::get_slice(params.modulus, params.modulus_len)?.to_vec();
        let raw_modulus = RawSRPModulus::new_with_bytes(modulus);
        let verifier = UnsafePtr::get_slice(params.verifier, params.verifier_len)?.to_vec();
        let verifier = ServerClientVerifier::new_with_bytes(verifier);
        let mut interaction = if !secret.is_null() && secret_len > 0 {
            let secret_len = checked_len(secret_len, "secret_len")?;
            let server_ephemeral_secret = UnsafePtr::get_slice(secret, secret_len)?.to_vec();
            let state = ServerInteractionState {
                server_ephemeral: None,
                server_ephemeral_secret: server_ephemeral_secret.into(),
            };
            ServerInteraction::restore(&raw_modulus, &verifier, &state)
                .map_err(|error| error.to_string())?
        } else {
            ServerInteraction::new(&raw_modulus, &verifier).map_err(|error| error.to_string())?
        };

        let challenge = interaction.generate_challenge();
        copy_to_host_buffer(
            &challenge.0,
            ephemeral_buffer,
            ephemeral_buffer_len,
            "ephemeral",
        )?;

        *UnsafePtr::ref_mut(out_server_handshake)? = UnsafePtr::new_raw(SrpServer {
            interaction: Mutex::new(interaction),
        });
        Ok(())
    })
}

/// Verifies the client proof and ephemeral and computes the server proof.
///
/// `(client_proof, client_proof_len)` and `(client_ephemeral, client_ephemeral_len)` are the client's
/// values; on successful verification the server proof is written into
/// `(server_proof_buffer, server_proof_buffer_len)`, failing if the buffer is too small.
///
/// # Safety
/// `ptr` must be a live server handle from `srp_server_generate_handshake`; `client_proof` and
/// `client_ephemeral` must each be valid for their lengths or null when zero; `server_proof_buffer`
/// must be non-null and writable for `server_proof_buffer_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn srp_server_compute_exchange(
    ptr: *const SrpServer,
    client_proof: *const u8,
    client_proof_len: i32,
    client_ephemeral: *const u8,
    client_ephemeral_len: usize,
    server_proof_buffer: *mut u8,
    server_proof_buffer_len: usize,
) -> InteropError {
    catch_error(|| {
        let mut interaction = UnsafePtr::as_ref(ptr)?
            .interaction
            .lock()
            .map_err(|_| "server interaction lock poisoned".to_string())?;
        let client_ephemeral_secret =
            UnsafePtr::get_slice(client_ephemeral, client_ephemeral_len)?.to_vec();
        let client_proof_len = checked_len(client_proof_len, "client_proof_len")?;
        let client_proof = UnsafePtr::get_slice(client_proof, client_proof_len)?.to_vec();
        let client = ServerClientProof::new_with_bytes(client_ephemeral_secret, client_proof)
            .map_err(|error| error.to_string())?;
        let proof = interaction
            .verify_proof(&client)
            .map_err(|error| error.to_string())?;

        copy_to_host_buffer(
            &proof.0,
            server_proof_buffer,
            server_proof_buffer_len,
            "server proof",
        )?;
        Ok(())
    })
}

/// Frees an SRP server handle created by `srp_server_generate_handshake`.
///
/// # Safety
/// `ptr` must be a live server handle from `srp_server_generate_handshake` and must not be reused
/// afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn srp_server_destroy(ptr: *mut SrpServer) {
    UnsafePtr::drop_raw(ptr);
}

#[cfg(test)]
mod tests;
