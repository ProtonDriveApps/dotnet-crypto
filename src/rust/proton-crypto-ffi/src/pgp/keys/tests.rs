use crate::pgp::keys::{
    KeyGenerationParameters, pgp_generate_key, pgp_generate_session_key,
    pgp_generate_session_key_aead, pgp_key_destroy, pgp_key_export, pgp_key_lock, pgp_key_unlock,
    pgp_locked_private_key_import, pgp_new_session_key_from_token,
    pgp_new_session_key_from_token_aead, pgp_private_key_get_public_key, pgp_private_key_import,
    pgp_private_key_import_unlock, pgp_public_key_import, pgp_session_key_destroy,
    pgp_session_key_export_token, pgp_session_key_get_algorithm, pgp_session_key_is_aead,
};

use crate::tests::*;
use test_case::test_case;

#[test]
fn ffi_pgp_public_key_import_succeeds_and_destroy() {
    let key = ARMORED_PUBLIC_KEY_V4.as_bytes();
    let mut h = std::ptr::null_mut();
    unsafe {
        pgp_public_key_import(key.as_ptr(), key.len(), 0, &mut h).abort_if_fail("import");
        pgp_key_destroy(h);
    }
}

#[test]
#[should_panic]
fn ffi_pgp_public_key_import_fails_on_garbage() {
    let garbage = b"not a key at all";
    let mut h = std::ptr::null_mut();
    unsafe {
        pgp_public_key_import(garbage.as_ptr(), garbage.len(), 0, &mut h)
            .abort_if_fail("import garbage");
    }
}

#[test]
fn ffi_pgp_locked_private_key_import() {
    let key = ARMORED_LOCKED_PRIVATE_KEY_V4.as_bytes();
    let mut h = std::ptr::null_mut();
    unsafe {
        pgp_locked_private_key_import(key.as_ptr(), key.len(), 0, &mut h)
            .abort_if_fail("import locked");
        pgp_key_destroy(h);
    }
}

#[test]
fn ffi_pgp_locked_private_key_import_and_unlock() {
    let key = ARMORED_LOCKED_PRIVATE_KEY_V4.as_bytes();
    let pass = PASSPHRASE;
    let mut h = std::ptr::null_mut();
    unsafe {
        pgp_private_key_import_unlock(
            key.as_ptr(),
            key.len(),
            pass.as_ptr(),
            pass.len(),
            0,
            &mut h,
        )
        .abort_if_fail("import locked and unlock");
        pgp_key_destroy(h);
    }
}

#[test]
fn ffi_pgp_private_key_import_unlock_succeeds() {
    unsafe {
        let h = priv_key_handle();
        pgp_key_destroy(h);
    }
}

#[test]
#[should_panic]
fn ffi_pgp_private_key_import_unlock_fails_wrong_passphrase() {
    let key = ARMORED_LOCKED_PRIVATE_KEY_V4.as_bytes();
    let bad = b"wrong-passphrase";
    let mut h = std::ptr::null_mut();
    unsafe {
        pgp_private_key_import_unlock(key.as_ptr(), key.len(), bad.as_ptr(), bad.len(), 0, &mut h)
            .abort_if_fail("import unlock bad pass");
    }
}

#[test]
fn ffi_pgp_private_key_get_public_key() {
    unsafe {
        let priv_h = priv_key_handle();
        let mut pub_h = std::ptr::null_mut();
        pgp_private_key_get_public_key(priv_h, &mut pub_h).abort_if_fail("get_pub_key");
        pgp_key_destroy(priv_h);
        pgp_key_destroy(pub_h);
    }
}

#[test]
fn ffi_pgp_private_key_get_public_key_null_out_returns_error() {
    unsafe {
        let priv_h = priv_key_handle();
        // A null out-pointer must be a clean error, not a null write.
        let result = pgp_private_key_get_public_key(priv_h, std::ptr::null_mut());
        assert!(!result.is_success());
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_key_export_armored_public() {
    unsafe {
        let h = pub_key_handle();
        let mut out = Vec::new();
        pgp_key_export(h, true, true, vec_writer(&mut out)).abort_if_fail("export armored");
        assert!(out.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        pgp_key_destroy(h);
    }
}

#[test]
fn ffi_pgp_key_lock_and_unlock_round_trips() {
    let pass = b"new-test-pass";
    unsafe {
        let priv_h = priv_key_handle();
        let mut locked_h = std::ptr::null_mut();
        pgp_key_lock(priv_h, pass.as_ptr(), pass.len(), &mut locked_h).abort_if_fail("lock");
        pgp_key_destroy(priv_h);

        let mut unlocked_h = std::ptr::null_mut();
        pgp_key_unlock(locked_h, pass.as_ptr(), pass.len(), &mut unlocked_h)
            .abort_if_fail("unlock");
        pgp_key_destroy(locked_h);
        pgp_key_destroy(unlocked_h);
    }
}

#[test]
#[should_panic]
fn ffi_pgp_key_unlock_fails_with_wrong_passphrase() {
    let pass = b"correct-pass";
    let wrong = b"wrong-pass";
    unsafe {
        let priv_h = priv_key_handle();
        let mut locked_h = std::ptr::null_mut();
        pgp_key_lock(priv_h, pass.as_ptr(), pass.len(), &mut locked_h).abort_if_fail("lock");
        pgp_key_destroy(priv_h);

        let mut out_h = std::ptr::null_mut();
        pgp_key_unlock(locked_h, wrong.as_ptr(), wrong.len(), &mut out_h)
            .abort_if_fail("unlock wrong pass");
        pgp_key_destroy(locked_h);
    }
}

fn generation_params() -> KeyGenerationParameters {
    let name = b"Test User";
    let email = b"test@example.com";
    KeyGenerationParameters {
        profile: 0,
        has_generation_time: false,
        has_user_id: true,
        name: name.as_ptr(),
        name_len: name.len(),
        email: email.as_ptr(),
        email_len: email.len(),
        generation_time: 0,
        algorithm: 0,
    }
}

#[test_case(0 ; "default_profile")]
#[test_case(1 ; "aead_profile")]
fn ffi_pgp_generate_key_succeeds(profile: u8) {
    let mut params = generation_params();
    params.profile = profile;
    let mut h = std::ptr::null_mut();
    unsafe {
        pgp_generate_key(&params, &mut h).abort_if_fail("generate_key");
        pgp_key_destroy(h);
    }
}

#[test]
fn ffi_pgp_generate_key_with_generation_time_succeeds() {
    let mut params = generation_params();
    params.has_generation_time = true;
    params.generation_time = unix_now();
    let mut h = std::ptr::null_mut();
    unsafe {
        pgp_generate_key(&params, &mut h).abort_if_fail("generate_key at time");
        pgp_key_destroy(h);
    }
}

#[test]
fn ffi_pgp_generate_key_invalid_algorithm_returns_error() {
    let mut params = generation_params();
    params.algorithm = 99;
    let mut h = std::ptr::null_mut();
    unsafe {
        let err = pgp_generate_key(&params, &mut h);
        assert!(!err.is_success(), "unknown algorithm id must be rejected");
        crate::interop_memory_free(err.message.cast_mut().cast());
    }
}

#[test]
fn ffi_pgp_private_key_export_and_import_round_trip() {
    unsafe {
        let priv_h = priv_key_handle();
        // Unlocked private export (armored), then re-import without a passphrase.
        let mut exported = Vec::new();
        pgp_key_export(priv_h, false, true, vec_writer(&mut exported))
            .abort_if_fail("export private");
        assert!(exported.starts_with(b"-----BEGIN PGP PRIVATE KEY BLOCK-----"));

        let mut imported_h = std::ptr::null_mut();
        pgp_private_key_import(exported.as_ptr(), exported.len(), 0, &mut imported_h)
            .abort_if_fail("import unlocked private");
        pgp_key_destroy(imported_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_key_export_unarmored_public() {
    unsafe {
        let h = pub_key_handle();
        let mut out = Vec::new();
        // force_public = false on a public handle exercises the public-key export arm.
        pgp_key_export(h, false, false, vec_writer(&mut out)).abort_if_fail("export unarmored");
        assert!(!out.is_empty());
        assert!(!out.starts_with(b"-----"));
        pgp_key_destroy(h);
    }
}

#[test]
fn ffi_pgp_locked_key_export_and_get_public_key() {
    let key = ARMORED_LOCKED_PRIVATE_KEY_V4.as_bytes();
    unsafe {
        let mut locked_h = std::ptr::null_mut();
        pgp_locked_private_key_import(key.as_ptr(), key.len(), 0, &mut locked_h)
            .abort_if_fail("import locked");

        // Public key derived from a locked handle.
        let mut pub_h = std::ptr::null_mut();
        pgp_private_key_get_public_key(locked_h, &mut pub_h).abort_if_fail("get_pub from locked");
        pgp_key_destroy(pub_h);

        // Locked private export keeps the key locked.
        let mut exported = Vec::new();
        pgp_key_export(locked_h, false, true, vec_writer(&mut exported))
            .abort_if_fail("export locked");
        assert!(exported.starts_with(b"-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        pgp_key_destroy(locked_h);
    }
}

#[test]
fn ffi_pgp_key_unlock_unlocked_key_returns_error() {
    let pass = b"any-pass";
    unsafe {
        let priv_h = priv_key_handle();
        let mut out_h = std::ptr::null_mut();
        let err = pgp_key_unlock(priv_h, pass.as_ptr(), pass.len(), &mut out_h);
        assert!(!err.is_success(), "unlocking an unlocked key must fail");
        crate::interop_memory_free(err.message.cast_mut().cast());
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_key_unlock_public_key_returns_error() {
    let pass = b"any-pass";
    unsafe {
        let pub_h = pub_key_handle();
        let mut out_h = std::ptr::null_mut();
        let err = pgp_key_unlock(pub_h, pass.as_ptr(), pass.len(), &mut out_h);
        assert!(!err.is_success(), "unlocking a public key must fail");
        crate::interop_memory_free(err.message.cast_mut().cast());
        pgp_key_destroy(pub_h);
    }
}

#[test]
fn ffi_pgp_key_unlock_null_passphrase_returns_error() {
    let key = ARMORED_LOCKED_PRIVATE_KEY_V4.as_bytes();
    unsafe {
        let mut locked_h = std::ptr::null_mut();
        pgp_locked_private_key_import(key.as_ptr(), key.len(), 0, &mut locked_h)
            .abort_if_fail("import locked");
        let mut out_h = std::ptr::null_mut();
        let err = pgp_key_unlock(locked_h, std::ptr::null(), 0, &mut out_h);
        assert!(!err.is_success(), "null passphrase must be rejected");
        crate::interop_memory_free(err.message.cast_mut().cast());
        pgp_key_destroy(locked_h);
    }
}

// Session-key cipher ids: 2 = TripleDES, 3 = CAST5, 7 = AES128, 8 = AES192, 9 = AES256.
#[test_case(2 ; "triple_des")]
#[test_case(3 ; "cast5")]
#[test_case(7 ; "aes128")]
#[test_case(8 ; "aes192")]
#[test_case(9 ; "aes256")]
fn ffi_pgp_session_key_cipher_id_round_trips(cipher: u8) {
    let token = session_key_token();
    let mut h = std::ptr::null_mut();
    unsafe {
        pgp_new_session_key_from_token(token.as_ptr(), token.len(), cipher, &mut h)
            .abort_if_fail("new_session_key");
        let mut out_cipher = 0u8;
        pgp_session_key_get_algorithm(h, &mut out_cipher).abort_if_fail("get_algorithm");
        assert_eq!(out_cipher, cipher);
        pgp_session_key_destroy(h);
    }
}

#[test]
fn ffi_pgp_new_session_key_invalid_cipher_returns_error() {
    let token = session_key_token();
    let mut h = std::ptr::null_mut();
    unsafe {
        let err = pgp_new_session_key_from_token(token.as_ptr(), token.len(), 5, &mut h);
        assert!(!err.is_success(), "unsupported cipher id must be rejected");
        crate::interop_memory_free(err.message.cast_mut().cast());
    }
}

#[test]
fn ffi_pgp_session_key_aead_algorithm_falls_back_to_token_length() {
    let token = session_key_token();
    let mut h = std::ptr::null_mut();
    unsafe {
        pgp_new_session_key_from_token_aead(token.as_ptr(), token.len(), 9, &mut h)
            .abort_if_fail("new_session_key_aead");
        let mut is_aead = false;
        pgp_session_key_is_aead(h, &mut is_aead).abort_if_fail("is_aead");
        assert!(is_aead);
        // AEAD keys store no algorithm; a 32-byte token falls back to AES256 (id 9).
        let mut cipher = 0u8;
        pgp_session_key_get_algorithm(h, &mut cipher).abort_if_fail("get_algorithm fallback");
        assert_eq!(cipher, 9);
        pgp_session_key_destroy(h);
    }
}

#[test]
fn ffi_pgp_session_key_from_token_export_and_destroy() {
    let token = session_key_token();
    let mut h = std::ptr::null_mut();
    unsafe {
        pgp_new_session_key_from_token(token.as_ptr(), token.len(), 9, &mut h)
            .abort_if_fail("new_session_key");
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len = 0usize;
        pgp_session_key_export_token(h, &mut out_ptr, &mut out_len).abort_if_fail("export_token");
        assert_eq!(out_len, token.len());
        let exported = std::slice::from_raw_parts(out_ptr, out_len);
        assert_eq!(exported, token.as_slice());
        crate::interop_memory_free(out_ptr.cast());
        pgp_session_key_destroy(h);
    }
}

#[test]
fn ffi_pgp_new_session_key_from_token_aead() {
    let token = session_key_token();
    let mut h = std::ptr::null_mut();
    unsafe {
        pgp_new_session_key_from_token_aead(token.as_ptr(), token.len(), 9, &mut h)
            .abort_if_fail("new_session_key_aead");
        pgp_session_key_destroy(h);
    }
}

#[test]
fn ffi_pgp_generate_session_key_get_algorithm_and_is_aead() {
    let mut h = std::ptr::null_mut();
    unsafe {
        pgp_generate_session_key(9, &mut h).abort_if_fail("generate_session_key");
        let mut cipher = 0u8;
        pgp_session_key_get_algorithm(h, &mut cipher).abort_if_fail("get_algorithm");
        assert_eq!(cipher, 9);
        let mut is_aead = true;
        pgp_session_key_is_aead(h, &mut is_aead).abort_if_fail("is_aead");
        assert!(!is_aead);
        pgp_session_key_destroy(h);
    }
}

#[test]
fn ffi_pgp_generate_session_key_aead() {
    let mut h = std::ptr::null_mut();
    unsafe {
        pgp_generate_session_key_aead(9, &mut h).abort_if_fail("generate_sk_aead");
        pgp_session_key_destroy(h);
    }
}
