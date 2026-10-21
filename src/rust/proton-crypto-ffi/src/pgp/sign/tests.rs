use crate::pgp::keys::{pgp_key_destroy, pgp_locked_private_key_import};
use crate::pgp::message::{
    pgp_message_writer_close, pgp_message_writer_destroy, pgp_message_writer_write,
};
use crate::pgp::sign::{
    pgp_sign, pgp_sign_stream, pgp_signing_context_new, pgp_signing_context_new_destroy,
};
use crate::pgp::tests::sign_params_for;
use crate::pgp::verify::tests::ver_params;
use crate::pgp::verify::{
    pgp_verification_result_destroy, pgp_verification_result_error, pgp_verify_detached,
};
use crate::tests::*;
use test_case::test_case;

#[test_case(KeyVersion::V4, 0 ; "v4 default_profile")]
#[test_case(KeyVersion::V4, 1 ; "v4 aead_profile")]
#[test_case(KeyVersion::V6, 0 ; "v6 default_profile")]
#[test_case(KeyVersion::V6, 1 ; "v6 aead_profile")]
fn ffi_pgp_sign_and_verify_detached_round_trip(version: KeyVersion, profile: u8) {
    unsafe {
        let pub_h = pub_key_handle_v(version);
        let priv_h = priv_key_handle_v(version);

        let sign_keys = [priv_h];
        let mut sp = sign_params_for(&sign_keys);
        sp.profile = profile;
        let mut sig = Vec::new();
        pgp_sign(
            &sp,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            true,
            vec_writer(&mut sig),
        )
        .abort_if_fail("sign detached");
        assert!(!sig.is_empty());

        let ver_keys = [pub_h];
        let vp = ver_params(&ver_keys);
        let mut vr_h = std::ptr::null_mut();
        pgp_verify_detached(
            &vp,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            sig.as_ptr(),
            sig.len(),
            1,
            &mut vr_h,
        )
        .abort_if_fail("verify_detached");
        let mut status = -1i32;
        pgp_verification_result_error(vr_h, &mut status).abort_if_fail("vr_error");
        assert_eq!(status, 0);
        pgp_verification_result_destroy(vr_h);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test_case(KeyVersion::V4, 0 ; "v4 default_profile")]
#[test_case(KeyVersion::V4, 1 ; "v4 aead_profile")]
#[test_case(KeyVersion::V6, 0 ; "v6 default_profile")]
#[test_case(KeyVersion::V6, 1 ; "v6 aead_profile")]
fn ffi_pgp_sign_stream_and_verify_detached(version: KeyVersion, profile: u8) {
    unsafe {
        let pub_h = pub_key_handle_v(version);
        let priv_h = priv_key_handle_v(version);
        let sign_keys = [priv_h];
        let mut sp = sign_params_for(&sign_keys);
        sp.profile = profile;

        let mut sig = Vec::new();
        let mut writer_h = std::ptr::null_mut();
        pgp_sign_stream(&sp, vec_writer(&mut sig), 1, true, None, &mut writer_h)
            .abort_if_fail("sign stream open");
        let mut written = 0usize;
        pgp_message_writer_write(
            writer_h,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            &mut written,
        )
        .abort_if_fail("sign_stream write");
        assert_eq!(written, PLAIN_TEXT.len());
        pgp_message_writer_close(writer_h).abort_if_fail("sign_stream close");
        pgp_message_writer_destroy(writer_h);
        assert!(!sig.is_empty());

        let ver_keys = [pub_h];
        let vp = ver_params(&ver_keys);
        let mut vr_h = std::ptr::null_mut();
        pgp_verify_detached(
            &vp,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            sig.as_ptr(),
            sig.len(),
            1,
            &mut vr_h,
        )
        .abort_if_fail("verify after stream sign");
        let mut status = -1i32;
        pgp_verification_result_error(vr_h, &mut status).abort_if_fail("vr_error");
        assert_eq!(status, 0);
        pgp_verification_result_destroy(vr_h);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_signing_context_new_and_destroy() {
    let value = b"proton.drive.v1";
    let mut h = std::ptr::null_mut();
    unsafe {
        pgp_signing_context_new(value.as_ptr(), value.len(), true, &mut h)
            .abort_if_fail("signing_context_new");
        pgp_signing_context_new_destroy(h);
    }
}

// The inline (non-detached) outputs cannot be verified through `pgp_verify_inline`: that entry
// point is decryptor-based and rejects signed-but-unencrypted messages ("Message is not
// encrypted"). Assert the produced inline message instead.
#[test]
fn ffi_pgp_sign_inline_produces_pgp_message() {
    unsafe {
        let priv_h = priv_key_handle();

        let sign_keys = [priv_h];
        let sp = sign_params_for(&sign_keys);
        let mut msg = Vec::new();
        pgp_sign(
            &sp,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            0,
            false,
            vec_writer(&mut msg),
        )
        .abort_if_fail("sign inline");
        assert!(msg.starts_with(b"-----BEGIN PGP MESSAGE-----"));
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_sign_stream_inline_produces_pgp_message() {
    unsafe {
        let priv_h = priv_key_handle();
        let sign_keys = [priv_h];
        let sp = sign_params_for(&sign_keys);

        let mut msg = Vec::new();
        let mut writer_h = std::ptr::null_mut();
        pgp_sign_stream(&sp, vec_writer(&mut msg), 0, false, None, &mut writer_h)
            .abort_if_fail("inline sign stream open");
        let mut written = 0usize;
        pgp_message_writer_write(
            writer_h,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            &mut written,
        )
        .abort_if_fail("inline sign_stream write");
        assert_eq!(written, PLAIN_TEXT.len());
        pgp_message_writer_close(writer_h).abort_if_fail("inline sign_stream close");
        pgp_message_writer_destroy(writer_h);
        assert!(msg.starts_with(b"-----BEGIN PGP MESSAGE-----"));
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_sign_utf8_at_time_and_verify_at_time() {
    let time = unix_now();
    // Newline-free so utf8 canonicalization cannot alter the signed bytes.
    let message = b"utf8 signed message";
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();

        let sign_keys = [priv_h];
        let mut sp = sign_params_for(&sign_keys);
        sp.utf8 = true;
        sp.has_signing_time = true;
        sp.signing_time = time;
        let mut sig = Vec::new();
        pgp_sign(
            &sp,
            message.as_ptr(),
            message.len(),
            1,
            true,
            vec_writer(&mut sig),
        )
        .abort_if_fail("utf8 timed sign");

        let ver_keys = [pub_h];
        let mut vp = ver_params(&ver_keys);
        vp.is_utf8 = true;
        vp.has_verification_time = true;
        vp.verification_time = time;
        let mut vr_h = std::ptr::null_mut();
        pgp_verify_detached(
            &vp,
            message.as_ptr(),
            message.len(),
            sig.as_ptr(),
            sig.len(),
            1,
            &mut vr_h,
        )
        .abort_if_fail("utf8 timed verify");
        let mut status = -1i32;
        pgp_verification_result_error(vr_h, &mut status).abort_if_fail("vr_error");
        assert_eq!(status, 0);
        pgp_verification_result_destroy(vr_h);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_sign_with_locked_key_fails() {
    let key = ARMORED_LOCKED_PRIVATE_KEY_V4.as_bytes();
    unsafe {
        let mut locked_h = std::ptr::null_mut();
        pgp_locked_private_key_import(key.as_ptr(), key.len(), 0, &mut locked_h)
            .abort_if_fail("import locked");

        let sign_keys = [locked_h];
        let sp = sign_params_for(&sign_keys);
        let mut sig = Vec::new();
        let err = pgp_sign(
            &sp,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            true,
            vec_writer(&mut sig),
        );
        assert!(!err.is_success(), "locked signing key must be rejected");
        crate::interop_memory_free(err.message.cast_mut().cast());
        pgp_key_destroy(locked_h);
    }
}
