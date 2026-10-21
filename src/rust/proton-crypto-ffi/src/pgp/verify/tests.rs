use crate::pgp::keys::{PgpKey, pgp_key_destroy};
use crate::pgp::reader::{pgp_reader_destroy, pgp_verification_reader_get_verify_result};
use crate::pgp::sign::pgp_sign;
use crate::pgp::tests::sign_params_for;
use crate::pgp::verify::{
    SignatureInfo, Signatures, VerificationParameters, pgp_verification_context_destroy,
    pgp_verification_context_get_value, pgp_verification_context_is_required,
    pgp_verification_context_is_required_after, pgp_verification_context_new,
    pgp_verification_result_all_signatures, pgp_verification_result_destroy,
    pgp_verification_result_error, pgp_verification_result_signature_info, pgp_verify_detached,
    pgp_verify_detached_stream, pgp_verify_inline, pgp_verify_inline_stream,
};

use crate::tests::*;

pub(crate) fn ver_params(keys: &[*mut PgpKey]) -> VerificationParameters {
    VerificationParameters {
        keys_len: keys.len(),
        has_verification_time: false,
        has_verification_context: false,
        is_utf8: false,
        keys: keys.as_ptr().cast(),
        verification_context: std::ptr::null_mut(),
        verification_time: 0,
    }
}

#[test]
#[should_panic]
fn ffi_pgp_verify_detached_fails_on_invalid_signature() {
    unsafe {
        let pub_h = pub_key_handle();
        let ver_keys = [pub_h];
        let vp = ver_params(&ver_keys);
        let bad_sig = signature_v4_invalid();
        let mut vr_h = std::ptr::null_mut();
        pgp_verify_detached(
            &vp,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            bad_sig.as_ptr(),
            bad_sig.len(),
            1,
            &mut vr_h,
        )
        .abort_if_fail("verify_detached bad sig");
        let mut status = 0i32;
        pgp_verification_result_error(vr_h, &mut status).abort_if_fail("verification result");
        assert_ne!(status, 0);
        pgp_verification_result_destroy(vr_h);
        pgp_key_destroy(pub_h);
    }
}

#[test]
fn ffi_pgp_verify_detached_stream() {
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();
        let sign_keys = [priv_h];
        let sp = sign_params_for(&sign_keys);
        let mut sig = Vec::new();
        pgp_sign(
            &sp,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            true,
            vec_writer(&mut sig),
        )
        .abort_if_fail("sign");

        let (data_reader, _state) = make_reader(PLAIN_TEXT.to_vec());
        let ver_keys = [pub_h];
        let vp = ver_params(&ver_keys);
        let mut vr_h = std::ptr::null_mut();
        pgp_verify_detached_stream(&vp, data_reader, sig.as_ptr(), sig.len(), 1, &mut vr_h)
            .abort_if_fail("verify_detached_stream");
        let mut status = -1i32;
        pgp_verification_result_error(vr_h, &mut status).abort_if_fail("vr_error");
        assert_eq!(status, 0);
        pgp_verification_result_destroy(vr_h);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_verify_inline() {
    let msg = ARMORED_SIGNED_MESSAGE.as_bytes();
    unsafe {
        let priv_h = priv_key_handle();
        let keys = [priv_h];
        let vp = ver_params(&keys);
        let mut plaintext = Vec::new();
        let mut result = make_plaintext_result(&mut plaintext);
        pgp_verify_inline(&vp, msg.as_ptr(), msg.len(), 0, &mut result)
            .abort_if_fail("verify_inline");
        assert!(!plaintext.is_empty());
        assert!(result.has_verification_result);
        let mut status = -1i32;
        pgp_verification_result_error(result.verification_result, &mut status)
            .abort_if_fail("vr_error");
        assert_eq!(status, 0);
        pgp_verification_result_destroy(result.verification_result);
        pgp_key_destroy(priv_h);
    }
}

/// Regression: the single key array of the inline-verify entry points may mix public verification
/// keys with private decryption keys; public/locked handles must be skipped when collecting
/// decryption keys, not fail the whole call with "private key required".
#[test]
fn ffi_pgp_verify_inline_accepts_public_keys_in_key_array() {
    let msg = ARMORED_SIGNED_MESSAGE.as_bytes();
    unsafe {
        let priv_h = priv_key_handle();
        let pub_h = pub_key_handle();
        let keys = [priv_h, pub_h];
        let vp = ver_params(&keys);
        let mut plaintext = Vec::new();
        let mut result = make_plaintext_result(&mut plaintext);
        pgp_verify_inline(&vp, msg.as_ptr(), msg.len(), 0, &mut result)
            .abort_if_fail("verify_inline with mixed keys");
        assert!(!plaintext.is_empty());
        let mut status = -1i32;
        pgp_verification_result_error(result.verification_result, &mut status)
            .abort_if_fail("vr_error");
        assert_eq!(status, 0);
        pgp_verification_result_destroy(result.verification_result);
        pgp_key_destroy(priv_h);
        pgp_key_destroy(pub_h);
    }
}

/// Regression: same as [`ffi_pgp_verify_inline_accepts_public_keys_in_key_array`] for the
/// streaming variant.
#[test]
fn ffi_pgp_verify_inline_stream_accepts_public_keys_in_key_array() {
    let msg = ARMORED_SIGNED_MESSAGE.as_bytes();
    unsafe {
        let priv_h = priv_key_handle();
        let pub_h = pub_key_handle();
        let keys = [priv_h, pub_h];
        let vp = ver_params(&keys);
        let (msg_reader, _state) = make_reader(msg.to_vec());
        let mut reader_h = std::ptr::null_mut();
        pgp_verify_inline_stream(&vp, msg_reader, 0, &mut reader_h)
            .abort_if_fail("verify_inline_stream with mixed keys");
        let plaintext = drain_reader(reader_h);
        assert!(!plaintext.is_empty());

        let mut vr_h = std::ptr::null_mut();
        pgp_verification_reader_get_verify_result(reader_h, &mut vr_h)
            .abort_if_fail("get_verify_result");
        let mut status = -1i32;
        pgp_verification_result_error(vr_h, &mut status).abort_if_fail("vr_error");
        assert_eq!(status, 0);
        pgp_verification_result_destroy(vr_h);
        pgp_reader_destroy(reader_h);
        pgp_key_destroy(priv_h);
        pgp_key_destroy(pub_h);
    }
}

#[test]
fn ffi_pgp_verify_inline_stream() {
    let msg = ARMORED_SIGNED_MESSAGE.as_bytes();
    unsafe {
        let priv_h = priv_key_handle();
        let keys = [priv_h];
        let vp = ver_params(&keys);
        let (msg_reader, _state) = make_reader(msg.to_vec());
        let mut reader_h = std::ptr::null_mut();
        pgp_verify_inline_stream(&vp, msg_reader, 0, &mut reader_h)
            .abort_if_fail("verify_inline_stream open");
        let plaintext = drain_reader(reader_h);
        assert!(!plaintext.is_empty());

        let mut vr_h = std::ptr::null_mut();
        pgp_verification_reader_get_verify_result(reader_h, &mut vr_h)
            .abort_if_fail("get_verify_result");
        let mut status = -1i32;
        pgp_verification_result_error(vr_h, &mut status).abort_if_fail("vr_error");
        assert_eq!(status, 0);
        pgp_verification_result_destroy(vr_h);
        pgp_reader_destroy(reader_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_verify_detached_with_context_succeeds() {
    let value = b"proton.test.ctx";
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();

        let mut sc_h = std::ptr::null_mut();
        crate::pgp::sign::pgp_signing_context_new(value.as_ptr(), value.len(), true, &mut sc_h)
            .abort_if_fail("signing_context_new");
        let sign_keys = [priv_h];
        let mut sp = sign_params_for(&sign_keys);
        sp.has_signing_context = true;
        sp.signing_context = sc_h;
        let mut sig = Vec::new();
        pgp_sign(
            &sp,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            true,
            vec_writer(&mut sig),
        )
        .abort_if_fail("sign with context");

        let mut vc_h = std::ptr::null_mut();
        pgp_verification_context_new(value.as_ptr(), value.len(), true, 0, &mut vc_h)
            .abort_if_fail("verification_context_new");
        let ver_keys = [pub_h];
        let mut vp = ver_params(&ver_keys);
        vp.has_verification_context = true;
        vp.verification_context = vc_h;
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
        .abort_if_fail("verify_detached with context");
        let mut status = -1i32;
        pgp_verification_result_error(vr_h, &mut status).abort_if_fail("vr_error");
        assert_eq!(status, 0);
        pgp_verification_result_destroy(vr_h);
        crate::pgp::sign::pgp_signing_context_new_destroy(sc_h);
        pgp_verification_context_destroy(vc_h);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_verification_result_error_null_arguments() {
    unsafe {
        // Null status out-pointer.
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();
        let sign_keys = [priv_h];
        let sp = sign_params_for(&sign_keys);
        let mut sig = Vec::new();
        pgp_sign(
            &sp,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            true,
            vec_writer(&mut sig),
        )
        .abort_if_fail("sign");
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

        let err = pgp_verification_result_error(vr_h, std::ptr::null_mut());
        assert!(!err.is_success(), "null status pointer must be rejected");
        crate::interop_memory_free(err.message.cast_mut().cast());

        // Null result handle.
        let mut status = -1i32;
        let err = pgp_verification_result_error(std::ptr::null(), &mut status);
        assert!(!err.is_success(), "null handle must be rejected");
        crate::interop_memory_free(err.message.cast_mut().cast());

        pgp_verification_result_destroy(vr_h);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_verification_context_new_getters_and_destroy() {
    let value = b"proton.calendar.v1";
    let mut h = std::ptr::null_mut();
    unsafe {
        let time = unix_now();
        pgp_verification_context_new(value.as_ptr(), value.len(), true, time, &mut h)
            .abort_if_fail("vc_new");
        let mut out_value: *mut std::ffi::c_char = std::ptr::null_mut();
        pgp_verification_context_get_value(h, &mut out_value).abort_if_fail("vc_get_value");
        let s = std::ffi::CStr::from_ptr(out_value).to_str().expect("utf8");
        assert_eq!(s, "proton.calendar.v1");
        crate::interop_memory_free(out_value.cast());

        let mut is_req = false;
        pgp_verification_context_is_required(h, &mut is_req).abort_if_fail("vc_is_required");
        assert!(is_req);

        let mut req_after = 0;
        pgp_verification_context_is_required_after(h, &mut req_after).abort_if_fail("vc_req_after");
        assert_eq!(req_after, time);

        pgp_verification_context_destroy(h);
    }
}

#[test]
fn ffi_pgp_verification_result_signature_info_and_all_signatures() {
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();
        let sign_keys = [priv_h];
        let sp = sign_params_for(&sign_keys);
        let mut sig = Vec::new();
        pgp_sign(
            &sp,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            true,
            vec_writer(&mut sig),
        )
        .abort_if_fail("sign");
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

        let mut info = SignatureInfo {
            signature_type: 0,
            creation_time: 0,
            key_id: 0,
            key_fingerprint: std::ptr::null_mut(),
            key_fingerprint_len: 0,
            selected_signature: std::ptr::null_mut(),
            selected_signature_len: 0,
        };
        pgp_verification_result_signature_info(vr_h, &mut info).abort_if_fail("signature_info");
        assert!(info.creation_time > 0);
        assert_ne!(info.key_id, 0);
        if !info.selected_signature.is_null() {
            crate::interop_memory_free(info.selected_signature.cast());
        }

        let mut sigs = Signatures {
            number_of_signatures: 0,
            all_signatures: std::ptr::null_mut(),
            all_signatures_len: 0,
        };
        pgp_verification_result_all_signatures(vr_h, &mut sigs).abort_if_fail("all_signatures");
        assert_eq!(sigs.number_of_signatures, 1);
        assert!(!sigs.all_signatures.is_null());
        crate::interop_memory_free(sigs.all_signatures.cast());

        pgp_verification_result_destroy(vr_h);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}
