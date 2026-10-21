use crate::pgp::keys::pgp_key_destroy;
use crate::srp::client::{
    srp_auth_create, srp_auth_destroy, srp_client_handshake_compute, srp_client_handshake_destroy,
    srp_client_handshake_verify_proof, srp_get_modulus_verification_key,
};
use crate::srp::server::{
    srp_server_compute_exchange, srp_server_destroy, srp_server_generate_handshake,
};
use crate::srp::{ClientCreationParameters, ClientHandshakeBuffers, ServerCreationParameters};
use crate::tests::*;

#[test]
fn ffi_srp_server_generate_handshake_without_secret_succeeds() {
    let modulus = decode_b64(SRP_MODULUS_B64);
    let verifier = decode_b64(SRP_VERIFIER_B64);

    let server_params = ServerCreationParameters {
        modulus_len: modulus.len(),
        verifier_len: verifier.len(),
        modulus: modulus.as_ptr(),
        verifier: verifier.as_ptr(),
        bit_length: 2048,
    };
    let mut server_ephemeral_buf = vec![0u8; 512];
    let mut server_h = std::ptr::null_mut();
    unsafe {
        // No restored secret: the server generates a fresh interaction.
        srp_server_generate_handshake(
            &server_params,
            std::ptr::null(),
            0,
            server_ephemeral_buf.as_mut_ptr(),
            server_ephemeral_buf.len(),
            &mut server_h,
        )
        .abort_if_fail("fresh server_generate_handshake");
        assert!(
            server_ephemeral_buf.iter().any(|&b| b != 0),
            "challenge must be written to the ephemeral buffer"
        );
        srp_server_destroy(server_h);
    }
}

#[test]
fn ffi_srp_server_compute_exchange_small_proof_buffer_fails() {
    let username = SRP_USERNAME;
    let password = SRP_PASSWORD;
    let salt = decode_b64(SRP_SALT_B64);
    let signed_modulus = SRP_SIGNED_MODULUS.as_bytes();
    let modulus = decode_b64(SRP_MODULUS_B64);
    let verifier = decode_b64(SRP_VERIFIER_B64);
    let server_secret = decode_b64(SRP_SERVER_SECRET_B64);
    let server_ephemeral = decode_b64(SRP_SERVER_EPHEMERAL_B64);
    let srp_len = server_ephemeral.len();

    let server_params = ServerCreationParameters {
        modulus_len: modulus.len(),
        verifier_len: verifier.len(),
        modulus: modulus.as_ptr(),
        verifier: verifier.as_ptr(),
        bit_length: 2048,
    };
    let mut server_ephemeral_buf = vec![0u8; 512];
    let mut server_h = std::ptr::null_mut();
    unsafe {
        srp_server_generate_handshake(
            &server_params,
            server_secret.as_ptr(),
            server_secret.len() as i32,
            server_ephemeral_buf.as_mut_ptr(),
            server_ephemeral_buf.len(),
            &mut server_h,
        )
        .abort_if_fail("server_generate_handshake");

        let mut vk_h = std::ptr::null_mut();
        srp_get_modulus_verification_key(&mut vk_h).abort_if_fail("get_modulus_key");
        let auth_params = ClientCreationParameters {
            username_len: username.len(),
            password_len: password.len(),
            salt_len: salt.len(),
            signed_modulus_len: signed_modulus.len(),
            username: username.as_ptr(),
            password: password.as_ptr(),
            salt: salt.as_ptr(),
            signed_modulus: signed_modulus.as_ptr(),
        };
        let mut auth_h = std::ptr::null_mut();
        srp_auth_create(&auth_params, vk_h, &mut auth_h).abort_if_fail("auth_create");

        let mut proof_buf = vec![0u8; 512];
        let mut eph_buf = vec![0u8; 512];
        let mut buffers = ClientHandshakeBuffers {
            proof_buffer_len: proof_buf.len(),
            ephemeral_buffer_len: eph_buf.len(),
            proof_buffer: proof_buf.as_mut_ptr(),
            ephemeral_buffer: eph_buf.as_mut_ptr(),
        };
        let mut exchange_h = std::ptr::null_mut();
        srp_client_handshake_compute(
            auth_h,
            server_ephemeral.as_ptr(),
            server_ephemeral.len(),
            &mut buffers,
            2048,
            &mut exchange_h,
        )
        .abort_if_fail("client_handshake_compute");

        // A server-proof buffer too small for the proof must fail cleanly.
        let mut tiny_proof_buf = vec![0u8; 4];
        let err = srp_server_compute_exchange(
            server_h,
            proof_buf.as_ptr(),
            srp_len as i32,
            eph_buf.as_ptr(),
            srp_len,
            tiny_proof_buf.as_mut_ptr(),
            tiny_proof_buf.len(),
        );
        assert!(
            !err.is_success(),
            "undersized proof buffer must be rejected"
        );
        crate::interop_memory_free(err.message.cast_mut().cast());

        srp_client_handshake_destroy(exchange_h);
        srp_auth_destroy(auth_h);
        srp_server_destroy(server_h);
        pgp_key_destroy(vk_h);
    }
}

#[test]
fn ffi_srp_full_client_server_handshake_succeeds() {
    let username = SRP_USERNAME;
    let password = SRP_PASSWORD;
    let salt = decode_b64(SRP_SALT_B64);
    let signed_modulus = SRP_SIGNED_MODULUS.as_bytes();
    let modulus = decode_b64(SRP_MODULUS_B64);
    let verifier = decode_b64(SRP_VERIFIER_B64);
    let server_secret = decode_b64(SRP_SERVER_SECRET_B64);
    let server_ephemeral = decode_b64(SRP_SERVER_EPHEMERAL_B64);
    let srp_len = server_ephemeral.len();

    let server_params = ServerCreationParameters {
        modulus_len: modulus.len(),
        verifier_len: verifier.len(),
        modulus: modulus.as_ptr(),
        verifier: verifier.as_ptr(),
        bit_length: 2048,
    };
    let mut server_ephemeral_buf = vec![0u8; 512];
    let mut server_h = std::ptr::null_mut();
    unsafe {
        srp_server_generate_handshake(
            &server_params,
            server_secret.as_ptr(),
            server_secret.len() as i32,
            server_ephemeral_buf.as_mut_ptr(),
            server_ephemeral_buf.len(),
            &mut server_h,
        )
        .abort_if_fail("server_generate_handshake");

        let mut vk_h = std::ptr::null_mut();
        srp_get_modulus_verification_key(&mut vk_h).abort_if_fail("get_modulus_key");
        let auth_params = ClientCreationParameters {
            username_len: username.len(),
            password_len: password.len(),
            salt_len: salt.len(),
            signed_modulus_len: signed_modulus.len(),
            username: username.as_ptr(),
            password: password.as_ptr(),
            salt: salt.as_ptr(),
            signed_modulus: signed_modulus.as_ptr(),
        };
        let mut auth_h = std::ptr::null_mut();
        srp_auth_create(&auth_params, vk_h, &mut auth_h).abort_if_fail("auth_create");

        let mut proof_buf = vec![0u8; 512];
        let mut eph_buf = vec![0u8; 512];
        let mut buffers = ClientHandshakeBuffers {
            proof_buffer_len: proof_buf.len(),
            ephemeral_buffer_len: eph_buf.len(),
            proof_buffer: proof_buf.as_mut_ptr(),
            ephemeral_buffer: eph_buf.as_mut_ptr(),
        };
        let mut exchange_h = std::ptr::null_mut();
        srp_client_handshake_compute(
            auth_h,
            server_ephemeral.as_ptr(),
            server_ephemeral.len(),
            &mut buffers,
            2048,
            &mut exchange_h,
        )
        .abort_if_fail("client_handshake_compute");

        let mut server_proof_buf = vec![0u8; 512];
        srp_server_compute_exchange(
            server_h,
            proof_buf.as_ptr(),
            srp_len as i32,
            eph_buf.as_ptr(),
            srp_len,
            server_proof_buf.as_mut_ptr(),
            server_proof_buf.len(),
        )
        .abort_if_fail("server_compute_exchange");

        let mut is_valid = false;
        srp_client_handshake_verify_proof(
            exchange_h,
            server_proof_buf.as_ptr(),
            srp_len,
            &mut is_valid,
        )
        .abort_if_fail("client_verify_proof");
        assert!(is_valid, "server proof should be valid");

        srp_client_handshake_destroy(exchange_h);
        srp_auth_destroy(auth_h);
        srp_server_destroy(server_h);
        pgp_key_destroy(vk_h);
    }
}
