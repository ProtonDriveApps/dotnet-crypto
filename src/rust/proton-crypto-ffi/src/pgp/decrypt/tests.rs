use crate::interop::ForeignWriter;
use crate::pgp::encrypt::tests::enc_params;
use crate::tests::*;
use test_case::test_case;

use crate::pgp::decrypt::{
    DecryptionParameters, pgp_decrypt, pgp_decrypt_session_key, pgp_decrypt_stream,
};
use crate::pgp::encrypt::{pgp_encrypt, pgp_encrypt_session_key};
use crate::pgp::keys::{
    PgpKey, pgp_generate_session_key, pgp_generate_session_key_aead, pgp_key_destroy,
    pgp_session_key_destroy,
};
use crate::pgp::reader::{pgp_reader_destroy, pgp_verification_reader_get_verify_result};
use crate::pgp::sign::{pgp_signing_context_new, pgp_signing_context_new_destroy};
use crate::pgp::verify::{
    pgp_verification_context_destroy, pgp_verification_context_new,
    pgp_verification_result_destroy, pgp_verification_result_error,
    pgp_verification_result_signature_info,
};

pub(crate) fn dec_params(
    dec_keys: &[*mut PgpKey],
    ver_keys: &[*mut PgpKey],
) -> DecryptionParameters {
    DecryptionParameters {
        decryption_keys_len: dec_keys.len(),
        verification_keys_len: ver_keys.len(),
        password_len: 0,
        detached_sig_len: 0,
        has_session_key: false,
        has_verification_context: false,
        has_verification_time: false,
        utf8: false,
        detached_sig_is_encrypted: false,
        detached_sig_is_armored: false,
        decryption_keys: dec_keys.as_ptr().cast(),
        verification_keys: ver_keys.as_ptr().cast(),
        session_key: std::ptr::null_mut(),
        verification_context: std::ptr::null_mut(),
        verification_time: 0,
        password: std::ptr::null(),
        detached_sig: std::ptr::null(),
    }
}

#[test_case(KeyVersion::V4, 0 ; "v4 default_profile")]
#[test_case(KeyVersion::V4, 1 ; "v4 aead_profile")]
#[test_case(KeyVersion::V6, 0 ; "v6 default_profile")]
#[test_case(KeyVersion::V6, 1 ; "v6 aead_profile")]
fn ffi_pgp_encrypt_and_decrypt_round_trip(version: KeyVersion, profile: u8) {
    unsafe {
        let pub_h = pub_key_handle_v(version);
        let priv_h = priv_key_handle_v(version);

        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let mut ep = enc_params(&enc_keys, &sign_keys);
        ep.profile = profile;
        let mut ciphertext = Vec::new();
        pgp_encrypt(
            &ep,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            ForeignWriter::default(),
            vec_writer(&mut ciphertext),
        )
        .abort_if_fail("pgp_encrypt");
        assert!(!ciphertext.is_empty());

        let dec_keys = [priv_h];
        let ver_keys: [*mut PgpKey; 0] = [];
        let dp = dec_params(&dec_keys, &ver_keys);
        let mut plaintext = Vec::new();
        let mut result = make_plaintext_result(&mut plaintext);
        pgp_decrypt(&dp, ciphertext.as_ptr(), ciphertext.len(), 1, &mut result)
            .abort_if_fail("pgp_decrypt");
        assert_eq!(plaintext, PLAIN_TEXT);

        if result.has_verification_result {
            pgp_verification_result_destroy(result.verification_result);
        }
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test_case(KeyVersion::V4, false ; "v4 seipdv1 session key")]
#[test_case(KeyVersion::V6, true ; "v6 aead session key")]
fn ffi_pgp_encrypt_session_key_and_decrypt_session_key(version: KeyVersion, aead: bool) {
    unsafe {
        let pub_h = pub_key_handle_v(version);
        let priv_h = priv_key_handle_v(version);

        let mut sk_h = std::ptr::null_mut();
        if aead {
            pgp_generate_session_key_aead(9, &mut sk_h).abort_if_fail("gen_sk_aead");
        } else {
            pgp_generate_session_key(9, &mut sk_h).abort_if_fail("gen_sk");
        }

        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let ep = enc_params(&enc_keys, &sign_keys);
        let mut kp = Vec::new();
        pgp_encrypt_session_key(&ep, sk_h, vec_writer(&mut kp)).abort_if_fail("encrypt_sk");
        assert!(!kp.is_empty());

        let dec_keys = [priv_h];
        let ver_keys: [*mut PgpKey; 0] = [];
        let dp = dec_params(&dec_keys, &ver_keys);
        let mut out_sk_h = std::ptr::null_mut();
        pgp_decrypt_session_key(&dp, kp.as_ptr(), kp.len(), &mut out_sk_h)
            .abort_if_fail("decrypt_sk");

        pgp_session_key_destroy(sk_h);
        pgp_session_key_destroy(out_sk_h);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test_case(KeyVersion::V4, 0 ; "v4 default_profile")]
#[test_case(KeyVersion::V4, 1 ; "v4 aead_profile")]
#[test_case(KeyVersion::V6, 0 ; "v6 default_profile")]
#[test_case(KeyVersion::V6, 1 ; "v6 aead_profile")]
fn ffi_pgp_decrypt_stream_round_trip_and_verify_result(version: KeyVersion, profile: u8) {
    unsafe {
        let pub_h = pub_key_handle_v(version);
        let priv_h = priv_key_handle_v(version);

        let enc_keys = [pub_h];
        let sign_keys = [priv_h];
        let mut ep = enc_params(&enc_keys, &sign_keys);
        ep.profile = profile;
        let encoding = 1;
        let mut ciphertext = Vec::new();
        let mut signature = Vec::new();
        pgp_encrypt(
            &ep,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            encoding,
            vec_writer(&mut signature),
            vec_writer(&mut ciphertext),
        )
        .abort_if_fail("encrypt");
        let (ct_reader, _ct_state) = make_reader(ciphertext);
        let dec_keys = [priv_h];
        let ver_keys = [pub_h];
        let dp = dec_params(&dec_keys, &ver_keys);
        let mut reader_h = std::ptr::null_mut();
        pgp_decrypt_stream(&dp, ct_reader, 1, &mut reader_h).abort_if_fail("decrypt_stream open");
        let plaintext = drain_reader(reader_h);
        assert_eq!(plaintext.as_slice(), PLAIN_TEXT);

        let mut vr_h = std::ptr::null_mut();
        pgp_verification_reader_get_verify_result(reader_h, &mut vr_h)
            .abort_if_fail("get_verify_result");
        let mut status = 0i32;
        pgp_verification_result_error(vr_h, &mut status).abort_if_fail("verification result");
        assert_eq!(status, 0, "signature verification failure");
        pgp_verification_result_destroy(vr_h);
        pgp_reader_destroy(reader_h);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

// Destroying a decrypt-stream handle mid-stream is a plain drop — no worker to wait for — and
// must never block, whatever state the stream is in.
#[test]
fn ffi_pgp_decrypt_stream_destroy_mid_stream_does_not_hang() {
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();

        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let ep = enc_params(&enc_keys, &sign_keys);
        // Large enough that one small read leaves the stream mid-flight.
        let plaintext = vec![0u8; 1 << 20];
        let mut ciphertext = Vec::new();
        pgp_encrypt(
            &ep,
            plaintext.as_ptr(),
            plaintext.len(),
            1,
            ForeignWriter::default(),
            vec_writer(&mut ciphertext),
        )
        .abort_if_fail("encrypt");

        let (ct_reader, _ct_state) = make_reader(ciphertext);
        let dec_keys = [priv_h];
        let ver_keys: [*mut PgpKey; 0] = [];
        let dp = dec_params(&dec_keys, &ver_keys);
        let mut reader_h = std::ptr::null_mut();
        pgp_decrypt_stream(&dp, ct_reader, 1, &mut reader_h).abort_if_fail("decrypt_stream open");

        let mut buf = [0u8; 16];
        let mut n = 0usize;
        crate::pgp::reader::pgp_reader_read(reader_h, buf.as_mut_ptr(), buf.len(), &mut n)
            .abort_if_fail("read");
        assert!(n > 0);

        pgp_reader_destroy(reader_h);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

// After the verification result is taken the stream is finalized: further reads report end of
// stream and a second result request fails cleanly.
#[test]
fn ffi_pgp_reader_read_after_verify_result_returns_eof() {
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();

        let enc_keys = [pub_h];
        let sign_keys = [priv_h];
        let ep = enc_params(&enc_keys, &sign_keys);
        let mut ciphertext = Vec::new();
        let mut signature = Vec::new();
        pgp_encrypt(
            &ep,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            vec_writer(&mut signature),
            vec_writer(&mut ciphertext),
        )
        .abort_if_fail("encrypt");

        let (ct_reader, _ct_state) = make_reader(ciphertext);
        let dec_keys = [priv_h];
        let ver_keys = [pub_h];
        let dp = dec_params(&dec_keys, &ver_keys);
        let mut reader_h = std::ptr::null_mut();
        pgp_decrypt_stream(&dp, ct_reader, 1, &mut reader_h).abort_if_fail("decrypt_stream open");
        let plaintext = drain_reader(reader_h);
        assert_eq!(plaintext.as_slice(), PLAIN_TEXT);

        let mut vr_h = std::ptr::null_mut();
        pgp_verification_reader_get_verify_result(reader_h, &mut vr_h)
            .abort_if_fail("get_verify_result");
        pgp_verification_result_destroy(vr_h);

        // Finalized: reads report EOF instead of touching the consumed reader.
        let mut buf = [0u8; 16];
        let mut n = 7usize;
        crate::pgp::reader::pgp_reader_read(reader_h, buf.as_mut_ptr(), buf.len(), &mut n)
            .abort_if_fail("read after finalize");
        assert_eq!(n, 0);

        // And a second result request fails cleanly instead of double-consuming.
        let mut vr_h2 = std::ptr::null_mut();
        let err = pgp_verification_reader_get_verify_result(reader_h, &mut vr_h2);
        assert!(!err.is_success(), "second verify-result request must fail");
        crate::interop_memory_free(err.message.cast_mut().cast());

        pgp_reader_destroy(reader_h);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_decrypt_null_parameters_returns_error() {
    let err = unsafe {
        pgp_decrypt(
            std::ptr::null(),
            std::ptr::null(),
            0,
            1,
            std::ptr::null_mut(),
        )
    };
    assert!(!err.message.is_null(), "null parameters must be rejected");
    unsafe { crate::interop_memory_free(err.message.cast_mut().cast()) };
}

#[test]
fn ffi_pgp_encrypt_with_password_round_trip() {
    let password = b"test-password-123";
    unsafe {
        let enc_keys: [*mut PgpKey; 0] = [];
        let sign_keys: [*mut PgpKey; 0] = [];
        let mut ep = enc_params(&enc_keys, &sign_keys);
        ep.password = password.as_ptr();
        ep.password_len = password.len();
        let mut ciphertext = Vec::new();
        pgp_encrypt(
            &ep,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            ForeignWriter::default(),
            vec_writer(&mut ciphertext),
        )
        .abort_if_fail("password encrypt");

        let dec_keys: [*mut PgpKey; 0] = [];
        let ver_keys: [*mut PgpKey; 0] = [];
        let mut dp = dec_params(&dec_keys, &ver_keys);
        dp.password = password.as_ptr();
        dp.password_len = password.len();
        let mut plaintext = Vec::new();
        let mut result = make_plaintext_result(&mut plaintext);
        pgp_decrypt(&dp, ciphertext.as_ptr(), ciphertext.len(), 1, &mut result)
            .abort_if_fail("password decrypt");
        assert_eq!(plaintext, PLAIN_TEXT);
        if result.has_verification_result {
            pgp_verification_result_destroy(result.verification_result);
        }
    }
}

#[test_case(false, 0 ; "seipdv1 default_profile")]
#[test_case(true, 1 ; "seipdv2 aead_profile")]
fn ffi_pgp_encrypt_with_session_key_round_trip(aead: bool, profile: u8) {
    unsafe {
        let mut sk_h = std::ptr::null_mut();
        if aead {
            pgp_generate_session_key_aead(9, &mut sk_h).abort_if_fail("gen_sk_aead");
        } else {
            pgp_generate_session_key(9, &mut sk_h).abort_if_fail("gen_sk");
        }

        let enc_keys: [*mut PgpKey; 0] = [];
        let sign_keys: [*mut PgpKey; 0] = [];
        let mut ep = enc_params(&enc_keys, &sign_keys);
        ep.profile = profile;
        ep.has_session_key = true;
        ep.session_key = sk_h;
        let mut data_packet = Vec::new();
        pgp_encrypt(
            &ep,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            ForeignWriter::default(),
            vec_writer(&mut data_packet),
        )
        .abort_if_fail("session key encrypt");

        let dec_keys: [*mut PgpKey; 0] = [];
        let ver_keys: [*mut PgpKey; 0] = [];
        let mut dp = dec_params(&dec_keys, &ver_keys);
        dp.has_session_key = true;
        dp.session_key = sk_h;
        let mut plaintext = Vec::new();
        let mut result = make_plaintext_result(&mut plaintext);
        pgp_decrypt(&dp, data_packet.as_ptr(), data_packet.len(), 1, &mut result)
            .abort_if_fail("session key decrypt");
        assert_eq!(plaintext, PLAIN_TEXT);
        if result.has_verification_result {
            pgp_verification_result_destroy(result.verification_result);
        }
        pgp_session_key_destroy(sk_h);
    }
}

#[test_case(1, false ; "unarmored")]
#[test_case(0, false ; "armored")]
#[test_case(1, true ; "encrypted")]
fn ffi_pgp_encrypt_detached_signature_round_trip(encoding: u8, encrypted: bool) {
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();

        let enc_keys = [pub_h];
        let sign_keys = [priv_h];
        let mut ep = enc_params(&enc_keys, &sign_keys);
        ep.detached_sig = true;
        ep.detached_sig_encrypted = encrypted;
        let mut ciphertext = Vec::new();
        let mut signature = Vec::new();
        pgp_encrypt(
            &ep,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            encoding,
            vec_writer(&mut signature),
            vec_writer(&mut ciphertext),
        )
        .abort_if_fail("detached encrypt");
        assert!(!signature.is_empty());

        let dec_keys = [priv_h];
        let ver_keys = [pub_h];
        let mut dp = dec_params(&dec_keys, &ver_keys);
        dp.detached_sig = signature.as_ptr();
        dp.detached_sig_len = signature.len();
        // `pgp_encrypt` writes the signature armored for everything except explicit unarmored.
        dp.detached_sig_is_armored = encoding != 1;
        dp.detached_sig_is_encrypted = encrypted;
        let mut plaintext = Vec::new();
        let mut result = make_plaintext_result(&mut plaintext);
        pgp_decrypt(
            &dp,
            ciphertext.as_ptr(),
            ciphertext.len(),
            encoding,
            &mut result,
        )
        .abort_if_fail("detached decrypt");
        assert_eq!(plaintext, PLAIN_TEXT);
        assert!(result.has_verification_result);
        let mut status = -1i32;
        pgp_verification_result_error(result.verification_result, &mut status)
            .abort_if_fail("vr_error");
        assert_eq!(status, 0, "detached signature should verify");
        pgp_verification_result_destroy(result.verification_result);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_encrypt_detached_signature_without_sink_fails() {
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();
        let enc_keys = [pub_h];
        let sign_keys = [priv_h];
        let mut ep = enc_params(&enc_keys, &sign_keys);
        ep.detached_sig = true;
        let mut ciphertext = Vec::new();
        let err = pgp_encrypt(
            &ep,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            ForeignWriter::default(),
            vec_writer(&mut ciphertext),
        );
        assert!(!err.is_success(), "missing signature sink must be rejected");
        crate::interop_memory_free(err.message.cast_mut().cast());
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_encrypt_detached_signature_without_signing_keys_fails() {
    unsafe {
        let pub_h = pub_key_handle();
        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let mut ep = enc_params(&enc_keys, &sign_keys);
        ep.detached_sig = true;
        let mut ciphertext = Vec::new();
        let mut signature = Vec::new();
        let err = pgp_encrypt(
            &ep,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            vec_writer(&mut signature),
            vec_writer(&mut ciphertext),
        );
        assert!(!err.is_success(), "missing signing keys must be rejected");
        crate::interop_memory_free(err.message.cast_mut().cast());
        pgp_key_destroy(pub_h);
    }
}

#[test_case(b"test.context" as &[u8], 0 ; "matching context verifies")]
#[test_case(b"other.context" as &[u8], 4 ; "wrong context is bad context")]
fn ffi_pgp_encrypt_with_signing_context_and_verify(verify_value: &[u8], expected_status: i32) {
    let sign_value = b"test.context";
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();

        let mut sc_h = std::ptr::null_mut();
        pgp_signing_context_new(sign_value.as_ptr(), sign_value.len(), true, &mut sc_h)
            .abort_if_fail("signing_context_new");
        let enc_keys = [pub_h];
        let sign_keys = [priv_h];
        let mut ep = enc_params(&enc_keys, &sign_keys);
        ep.has_signing_context = true;
        ep.signing_context = sc_h;
        let mut ciphertext = Vec::new();
        pgp_encrypt(
            &ep,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            ForeignWriter::default(),
            vec_writer(&mut ciphertext),
        )
        .abort_if_fail("context encrypt");

        let mut vc_h = std::ptr::null_mut();
        pgp_verification_context_new(
            verify_value.as_ptr(),
            verify_value.len(),
            true,
            0,
            &mut vc_h,
        )
        .abort_if_fail("verification_context_new");
        let dec_keys = [priv_h];
        let ver_keys = [pub_h];
        let mut dp = dec_params(&dec_keys, &ver_keys);
        dp.has_verification_context = true;
        dp.verification_context = vc_h;
        let mut plaintext = Vec::new();
        let mut result = make_plaintext_result(&mut plaintext);
        pgp_decrypt(&dp, ciphertext.as_ptr(), ciphertext.len(), 1, &mut result)
            .abort_if_fail("context decrypt");
        assert_eq!(plaintext, PLAIN_TEXT);
        assert!(result.has_verification_result);
        let mut status = -1i32;
        let err = pgp_verification_result_error(result.verification_result, &mut status);
        assert_eq!(status, expected_status);
        if !err.is_success() {
            crate::interop_memory_free(err.message.cast_mut().cast());
        }
        pgp_verification_result_destroy(result.verification_result);
        pgp_signing_context_new_destroy(sc_h);
        pgp_verification_context_destroy(vc_h);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_encrypt_at_time_and_verify_at_time_round_trip() {
    let time = unix_now();
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();

        let enc_keys = [pub_h];
        let sign_keys = [priv_h];
        let mut ep = enc_params(&enc_keys, &sign_keys);
        ep.has_encryption_time = true;
        ep.encryption_time = time;
        let mut ciphertext = Vec::new();
        pgp_encrypt(
            &ep,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            ForeignWriter::default(),
            vec_writer(&mut ciphertext),
        )
        .abort_if_fail("timed encrypt");

        let dec_keys = [priv_h];
        let ver_keys = [pub_h];
        let mut dp = dec_params(&dec_keys, &ver_keys);
        dp.has_verification_time = true;
        dp.verification_time = time;
        let mut plaintext = Vec::new();
        let mut result = make_plaintext_result(&mut plaintext);
        pgp_decrypt(&dp, ciphertext.as_ptr(), ciphertext.len(), 1, &mut result)
            .abort_if_fail("timed decrypt");
        assert_eq!(plaintext, PLAIN_TEXT);
        assert!(result.has_verification_result);
        let mut status = -1i32;
        pgp_verification_result_error(result.verification_result, &mut status)
            .abort_if_fail("vr_error");
        assert_eq!(status, 0);
        pgp_verification_result_destroy(result.verification_result);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_encrypt_compressed_round_trip() {
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();

        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let mut ep = enc_params(&enc_keys, &sign_keys);
        ep.compress = true;
        let mut ciphertext = Vec::new();
        pgp_encrypt(
            &ep,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            ForeignWriter::default(),
            vec_writer(&mut ciphertext),
        )
        .abort_if_fail("compressed encrypt");

        let dec_keys = [priv_h];
        let ver_keys: [*mut PgpKey; 0] = [];
        let dp = dec_params(&dec_keys, &ver_keys);
        let mut plaintext = Vec::new();
        let mut result = make_plaintext_result(&mut plaintext);
        pgp_decrypt(&dp, ciphertext.as_ptr(), ciphertext.len(), 1, &mut result)
            .abort_if_fail("compressed decrypt");
        assert_eq!(plaintext, PLAIN_TEXT);
        if result.has_verification_result {
            pgp_verification_result_destroy(result.verification_result);
        }
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_encrypt_utf8_round_trip() {
    // Newline-free so utf8 line-ending canonicalization cannot alter the round trip.
    let message = b"utf8 plain text message";
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();

        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let mut ep = enc_params(&enc_keys, &sign_keys);
        ep.utf8 = true;
        let mut ciphertext = Vec::new();
        pgp_encrypt(
            &ep,
            message.as_ptr(),
            message.len(),
            1,
            ForeignWriter::default(),
            vec_writer(&mut ciphertext),
        )
        .abort_if_fail("utf8 encrypt");

        let dec_keys = [priv_h];
        let ver_keys: [*mut PgpKey; 0] = [];
        let mut dp = dec_params(&dec_keys, &ver_keys);
        dp.utf8 = true;
        let mut plaintext = Vec::new();
        let mut result = make_plaintext_result(&mut plaintext);
        pgp_decrypt(&dp, ciphertext.as_ptr(), ciphertext.len(), 1, &mut result)
            .abort_if_fail("utf8 decrypt");
        assert_eq!(plaintext, message);
        if result.has_verification_result {
            pgp_verification_result_destroy(result.verification_result);
        }
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_encrypt_armored_and_decrypt_auto_round_trip() {
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();

        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let ep = enc_params(&enc_keys, &sign_keys);
        let mut ciphertext = Vec::new();
        pgp_encrypt(
            &ep,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            0,
            ForeignWriter::default(),
            vec_writer(&mut ciphertext),
        )
        .abort_if_fail("armored encrypt");
        assert!(ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"));

        let dec_keys = [priv_h];
        let ver_keys: [*mut PgpKey; 0] = [];
        let dp = dec_params(&dec_keys, &ver_keys);
        let mut plaintext = Vec::new();
        let mut result = make_plaintext_result(&mut plaintext);
        // Encoding 2 = auto-detect.
        pgp_decrypt(&dp, ciphertext.as_ptr(), ciphertext.len(), 2, &mut result)
            .abort_if_fail("auto decrypt");
        assert_eq!(plaintext, PLAIN_TEXT);
        if result.has_verification_result {
            pgp_verification_result_destroy(result.verification_result);
        }
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_decrypt_invalid_encoding_returns_error() {
    unsafe {
        let dec_keys: [*mut PgpKey; 0] = [];
        let ver_keys: [*mut PgpKey; 0] = [];
        let dp = dec_params(&dec_keys, &ver_keys);
        let mut plaintext = Vec::new();
        let mut result = make_plaintext_result(&mut plaintext);
        let body = [0u8; 4];
        let err = pgp_decrypt(&dp, body.as_ptr(), body.len(), 9, &mut result);
        assert!(!err.is_success(), "invalid encoding id must be rejected");
        crate::interop_memory_free(err.message.cast_mut().cast());
    }
}

#[test]
fn ffi_pgp_decrypt_unsigned_with_verification_keys_returns_not_signed_status() {
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();

        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let ep = enc_params(&enc_keys, &sign_keys);
        let mut ciphertext = Vec::new();
        pgp_encrypt(
            &ep,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            ForeignWriter::default(),
            vec_writer(&mut ciphertext),
        )
        .abort_if_fail("encrypt unsigned");

        let dec_keys = [priv_h];
        let ver_keys = [pub_h];
        let dp = dec_params(&dec_keys, &ver_keys);
        let mut plaintext = Vec::new();
        let mut result = make_plaintext_result(&mut plaintext);
        pgp_decrypt(&dp, ciphertext.as_ptr(), ciphertext.len(), 1, &mut result)
            .abort_if_fail("decrypt unsigned");
        assert_eq!(plaintext, PLAIN_TEXT);
        assert!(result.has_verification_result);

        let mut status = -1i32;
        let err = pgp_verification_result_error(result.verification_result, &mut status);
        assert_eq!(status, 1, "unsigned message should report NotSigned");
        assert!(!err.is_success(), "NotSigned should carry an error message");
        crate::interop_memory_free(err.message.cast_mut().cast());

        // A result with no signature has no signature info to report.
        let mut info = std::mem::zeroed();
        let err = pgp_verification_result_signature_info(result.verification_result, &mut info);
        assert!(
            !err.is_success(),
            "signature info without signature must fail"
        );
        crate::interop_memory_free(err.message.cast_mut().cast());

        pgp_verification_result_destroy(result.verification_result);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_decrypt_with_non_matching_verifier_returns_no_verifier_status() {
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();
        let other_pub_h = pub_key_handle_v(KeyVersion::V6);

        let enc_keys = [pub_h];
        let sign_keys = [priv_h];
        let ep = enc_params(&enc_keys, &sign_keys);
        let mut ciphertext = Vec::new();
        pgp_encrypt(
            &ep,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            1,
            ForeignWriter::default(),
            vec_writer(&mut ciphertext),
        )
        .abort_if_fail("encrypt signed");

        let dec_keys = [priv_h];
        let ver_keys = [other_pub_h];
        let dp = dec_params(&dec_keys, &ver_keys);
        let mut plaintext = Vec::new();
        let mut result = make_plaintext_result(&mut plaintext);
        pgp_decrypt(&dp, ciphertext.as_ptr(), ciphertext.len(), 1, &mut result)
            .abort_if_fail("decrypt with wrong verifier");
        assert_eq!(plaintext, PLAIN_TEXT);
        assert!(result.has_verification_result);

        let mut status = -1i32;
        let err = pgp_verification_result_error(result.verification_result, &mut status);
        assert_eq!(status, 2, "non-matching verifier should report NoVerifier");
        assert!(!err.is_success());
        crate::interop_memory_free(err.message.cast_mut().cast());

        pgp_verification_result_destroy(result.verification_result);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
        pgp_key_destroy(other_pub_h);
    }
}
