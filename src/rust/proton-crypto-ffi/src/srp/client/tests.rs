use crate::pgp::keys::pgp_key_destroy;
use crate::srp::ClientCreationParameters;
use crate::srp::client::{
    srp_auth_create, srp_auth_derive_verifier, srp_auth_destroy, srp_get_modulus_verification_key,
};
use crate::tests::*;

use crate::srp::client::hash_password;

#[test]
fn ffi_srp_get_modulus_verification_key() {
    unsafe {
        let mut h = std::ptr::null_mut();
        srp_get_modulus_verification_key(&mut h).abort_if_fail("get_modulus_key");
        pgp_key_destroy(h);
    }
}

#[test]
fn ffi_srp_auth_create_and_destroy() {
    let username = SRP_USERNAME;
    let password = SRP_PASSWORD;
    let salt = decode_b64(SRP_SALT_B64);
    let signed_modulus = SRP_SIGNED_MODULUS.as_bytes();

    unsafe {
        let mut vk_h = std::ptr::null_mut();
        srp_get_modulus_verification_key(&mut vk_h).abort_if_fail("get_modulus_key");
        let params = ClientCreationParameters {
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
        srp_auth_create(&params, vk_h, &mut auth_h).abort_if_fail("auth_create");
        srp_auth_destroy(auth_h);
        pgp_key_destroy(vk_h);
    }
}

#[test]
fn ffi_srp_auth_derive_verifier_matches_test_vector() {
    let username = SRP_USERNAME;
    let password = SRP_PASSWORD;
    let salt = decode_b64(SRP_SALT_B64);
    let signed_modulus = SRP_SIGNED_MODULUS.as_bytes();
    let expected = decode_b64(SRP_VERIFIER_B64);

    unsafe {
        let mut vk_h = std::ptr::null_mut();
        srp_get_modulus_verification_key(&mut vk_h).abort_if_fail("get_modulus_key");
        let params = ClientCreationParameters {
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
        srp_auth_create(&params, vk_h, &mut auth_h).abort_if_fail("auth_create");

        let mut verifier_buf = vec![0u8; 512];
        srp_auth_derive_verifier(auth_h, verifier_buf.as_mut_ptr(), verifier_buf.len(), 2048)
            .abort_if_fail("derive_verifier");
        assert_eq!(&verifier_buf[..expected.len()], expected.as_slice());

        srp_auth_destroy(auth_h);
        pgp_key_destroy(vk_h);
    }
}

#[test]
fn ffi_hash_password_matches_test_vector() {
    let salt = decode_b64(SRP_PASSWORD_HASHING_SALT_B64);
    let expected = SRP_DERIVED_PASSWORD.as_bytes();
    let mut digest = vec![0u8; expected.len()];
    unsafe {
        hash_password(
            SRP_PASSWORD.as_ptr(),
            SRP_PASSWORD.len(),
            salt.as_ptr(),
            salt.len(),
            digest.as_mut_ptr(),
            digest.len(),
        )
        .abort_if_fail("hash_password");
    }
    assert_eq!(&digest[..expected.len()], expected);
}

#[test]
fn ffi_srp_get_modulus_verification_key_null_out_returns_error() {
    let err = unsafe { srp_get_modulus_verification_key(std::ptr::null_mut()) };
    assert!(
        !err.message.is_null(),
        "null output pointer must be rejected"
    );
    unsafe { crate::interop_memory_free(err.message.cast_mut().cast()) };
}
