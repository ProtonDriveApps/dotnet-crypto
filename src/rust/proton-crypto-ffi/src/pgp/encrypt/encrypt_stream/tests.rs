use crate::interop::{ForeignWriter, InteropError};
use crate::pgp::decrypt::tests::dec_params;
use crate::pgp::encrypt::tests::enc_params;
use crate::tests::*;
use std::ffi::c_void;
use test_case::test_case;

use crate::pgp::decrypt::pgp_decrypt;
use crate::pgp::encrypt::encrypt_stream::{
    EncryptReaderHandle, pgp_encrypt_reader_destroy, pgp_encrypt_reader_open,
    pgp_encrypt_reader_read_async, pgp_encrypt_reader_read_blocking,
};
use crate::pgp::keys::{PgpKey, pgp_key_destroy};
use crate::pgp::verify::tests::ver_params;
use crate::pgp::verify::{
    pgp_verification_result_destroy, pgp_verification_result_error, pgp_verify_detached,
};

use std::sync::{Condvar, Mutex};

fn drain_encrypt_reader(handle: *mut EncryptReaderHandle) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        let mut n = 0usize;
        unsafe { pgp_encrypt_reader_read_blocking(handle, buf.as_mut_ptr(), buf.len(), &mut n) }
            .abort_if_fail("er_read_blocking");
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    out
}

fn decrypt_expecting(
    dec_key: *mut PgpKey,
    ciphertext: &[u8],
    encoding: u8,
    expected_plaintext: &[u8],
) {
    unsafe {
        let dec_keys = [dec_key];
        let ver_keys: [*mut PgpKey; 0] = [];
        let dp = dec_params(&dec_keys, &ver_keys);
        let mut plaintext = Vec::new();
        let mut result = make_plaintext_result(&mut plaintext);
        pgp_decrypt(
            &dp,
            ciphertext.as_ptr(),
            ciphertext.len(),
            encoding,
            &mut result,
        )
        .abort_if_fail("pgp_decrypt");
        assert_eq!(plaintext, expected_plaintext);
        if result.has_verification_result {
            crate::pgp::verify::pgp_verification_result_destroy(result.verification_result);
        }
    }
}

#[test_case(KeyVersion::V4, 0 ; "v4 default_profile")]
#[test_case(KeyVersion::V4, 1 ; "v4 aead_profile")]
#[test_case(KeyVersion::V6, 0 ; "v6 default_profile")]
#[test_case(KeyVersion::V6, 1 ; "v6 aead_profile")]
fn ffi_pgp_encrypt_reader_open_read_blocking_decrypt_round_trip(version: KeyVersion, profile: u8) {
    unsafe {
        let pub_h = pub_key_handle_v(version);
        let priv_h = priv_key_handle_v(version);
        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let mut ep = enc_params(&enc_keys, &sign_keys);
        ep.profile = profile;
        let (pt_reader, _pt_state) = make_reader(PLAIN_TEXT.to_vec());
        let mut er_h = std::ptr::null_mut();
        pgp_encrypt_reader_open(
            &ep,
            pt_reader,
            ForeignWriter::default(),
            ForeignWriter::default(),
            1,
            None,
            &mut er_h,
        )
        .abort_if_fail("er_open");

        let ciphertext = drain_encrypt_reader(er_h);
        assert!(!ciphertext.is_empty());
        pgp_encrypt_reader_destroy(er_h);

        decrypt_expecting(priv_h, &ciphertext, 1, PLAIN_TEXT);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

// Destroying the handle mid-stream must close the request queue and unpark the worker (parked in
// its sink waiting for the next read) before waiting for its completion; if that ordering
// regresses, this test hangs instead of failing.
#[test]
fn ffi_pgp_encrypt_reader_destroy_mid_stream_does_not_hang() {
    unsafe {
        let pub_h = pub_key_handle();
        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let ep = enc_params(&enc_keys, &sign_keys);
        // Large enough that one small read leaves the stream (and its worker) mid-flight.
        let (pt_reader, _pt_state) = make_reader(vec![0u8; 1 << 20]);
        let mut er_h = std::ptr::null_mut();
        pgp_encrypt_reader_open(
            &ep,
            pt_reader,
            ForeignWriter::default(),
            ForeignWriter::default(),
            1,
            None,
            &mut er_h,
        )
        .abort_if_fail("er_open");

        let mut buf = [0u8; 16];
        let mut n = 0usize;
        pgp_encrypt_reader_read_blocking(er_h, buf.as_mut_ptr(), buf.len(), &mut n)
            .abort_if_fail("er_read_blocking");
        assert!(n > 0);

        pgp_encrypt_reader_destroy(er_h);
        pgp_key_destroy(pub_h);
    }
}

struct AsyncState {
    bytes: usize,
    error: bool,
    done: bool,
}

unsafe extern "C" fn async_cb(ctx: *mut c_void, n: usize, err: *const InteropError) {
    unsafe {
        let pair = &*(ctx as *const (Mutex<AsyncState>, Condvar));
        let mut g = pair.0.lock().unwrap();
        g.bytes += n;
        g.error = !err.is_null();
        if !err.is_null() {
            crate::interop_memory_free((*err).message.cast_mut().cast());
        }
        g.done = true;
        pair.1.notify_one();
    }
}

fn new_async_state() -> Box<(Mutex<AsyncState>, Condvar)> {
    Box::new((
        Mutex::new(AsyncState {
            bytes: 0,
            error: false,
            done: false,
        }),
        Condvar::new(),
    ))
}

fn wait_done(shared: &(Mutex<AsyncState>, Condvar)) -> (usize, bool) {
    let mut g = shared.0.lock().unwrap();
    while !g.done {
        g = shared.1.wait(g).unwrap();
    }
    (g.bytes, g.error)
}

#[test_case(KeyVersion::V4, 0 ; "v4 default_profile")]
#[test_case(KeyVersion::V4, 1 ; "v4 aead_profile")]
#[test_case(KeyVersion::V6, 0 ; "v6 default_profile")]
#[test_case(KeyVersion::V6, 1 ; "v6 aead_profile")]
fn ffi_pgp_encrypt_reader_read_async(version: KeyVersion, profile: u8) {
    unsafe {
        let pub_h = pub_key_handle_v(version);
        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let mut ep = enc_params(&enc_keys, &sign_keys);
        ep.profile = profile;
        let (pt_reader, _pt_state) = make_reader(PLAIN_TEXT.to_vec());
        let mut er_h = std::ptr::null_mut();
        pgp_encrypt_reader_open(
            &ep,
            pt_reader,
            ForeignWriter::default(),
            ForeignWriter::default(),
            1,
            None,
            &mut er_h,
        )
        .abort_if_fail("er_open");

        let shared = new_async_state();
        let ctx_ptr = &*shared as *const _ as *mut c_void;
        let mut buf = vec![0u8; 8192];
        pgp_encrypt_reader_read_async(er_h, buf.as_mut_ptr(), buf.len(), ctx_ptr, Some(async_cb))
            .abort_if_fail("er_read_async");

        let (bytes, error) = wait_done(&shared);
        assert!(!error);
        assert!(bytes > 0);

        pgp_encrypt_reader_destroy(er_h);
        pgp_key_destroy(pub_h);
    }
}

#[test]
fn ffi_pgp_encrypt_reader_split_round_trip() {
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();
        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let ep = enc_params(&enc_keys, &sign_keys);
        let (pt_reader, _pt_state) = make_reader(PLAIN_TEXT.to_vec());
        let mut key_packets = Vec::new();
        let mut er_h = std::ptr::null_mut();
        pgp_encrypt_reader_open(
            &ep,
            pt_reader,
            ForeignWriter::default(),
            vec_writer(&mut key_packets),
            1,
            None,
            &mut er_h,
        )
        .abort_if_fail("er_open split");

        let data_packet = drain_encrypt_reader(er_h);
        pgp_encrypt_reader_destroy(er_h);
        assert!(!key_packets.is_empty(), "split must emit key packets");
        assert!(!data_packet.is_empty(), "split must emit a data packet");

        let mut full_message = key_packets;
        full_message.extend_from_slice(&data_packet);
        decrypt_expecting(priv_h, &full_message, 1, PLAIN_TEXT);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_encrypt_reader_split_with_detached_signature() {
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();
        let enc_keys = [pub_h];
        let sign_keys = [priv_h];
        let mut ep = enc_params(&enc_keys, &sign_keys);
        ep.detached_sig = true;
        let (pt_reader, _pt_state) = make_reader(PLAIN_TEXT.to_vec());
        let mut key_packets = Vec::new();
        let mut signature = Vec::new();
        let mut er_h = std::ptr::null_mut();
        pgp_encrypt_reader_open(
            &ep,
            pt_reader,
            vec_writer(&mut signature),
            vec_writer(&mut key_packets),
            1,
            None,
            &mut er_h,
        )
        .abort_if_fail("er_open split detached");

        let data_packet = drain_encrypt_reader(er_h);
        pgp_encrypt_reader_destroy(er_h);
        assert!(!data_packet.is_empty());
        assert!(!signature.is_empty(), "detached signature must be written");

        // Split output is raw packets, so the detached signature is unarmored.
        let ver_keys = [pub_h];
        let vp = ver_params(&ver_keys);
        let mut vr_h = std::ptr::null_mut();
        pgp_verify_detached(
            &vp,
            PLAIN_TEXT.as_ptr(),
            PLAIN_TEXT.len(),
            signature.as_ptr(),
            signature.len(),
            1,
            &mut vr_h,
        )
        .abort_if_fail("verify split detached signature");
        let mut status = -1i32;
        pgp_verification_result_error(vr_h, &mut status).abort_if_fail("vr_error");
        assert_eq!(status, 0);
        pgp_verification_result_destroy(vr_h);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}

#[test]
fn ffi_pgp_encrypt_reader_detached_signature_armored_round_trip() {
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();
        let enc_keys = [pub_h];
        let sign_keys = [priv_h];
        let mut ep = enc_params(&enc_keys, &sign_keys);
        ep.detached_sig = true;
        let (pt_reader, _pt_state) = make_reader(PLAIN_TEXT.to_vec());
        let mut signature = Vec::new();
        let mut er_h = std::ptr::null_mut();
        pgp_encrypt_reader_open(
            &ep,
            pt_reader,
            vec_writer(&mut signature),
            ForeignWriter::default(),
            0,
            None,
            &mut er_h,
        )
        .abort_if_fail("er_open detached armored");

        let ciphertext = drain_encrypt_reader(er_h);
        pgp_encrypt_reader_destroy(er_h);
        assert!(ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"));
        assert!(signature.starts_with(b"-----BEGIN PGP SIGNATURE-----"));

        let dec_keys = [priv_h];
        let ver_keys = [pub_h];
        let mut dp = dec_params(&dec_keys, &ver_keys);
        dp.detached_sig = signature.as_ptr();
        dp.detached_sig_len = signature.len();
        dp.detached_sig_is_armored = true;
        let mut plaintext = Vec::new();
        let mut result = make_plaintext_result(&mut plaintext);
        pgp_decrypt(&dp, ciphertext.as_ptr(), ciphertext.len(), 0, &mut result)
            .abort_if_fail("decrypt armored with detached sig");
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
fn ffi_pgp_encrypt_reader_failing_plaintext_blocking_read_reports_error() {
    unsafe {
        let pub_h = pub_key_handle();
        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let ep = enc_params(&enc_keys, &sign_keys);
        let mut er_h = std::ptr::null_mut();
        pgp_encrypt_reader_open(
            &ep,
            make_failing_reader(),
            ForeignWriter::default(),
            ForeignWriter::default(),
            1,
            None,
            &mut er_h,
        )
        .abort_if_fail("er_open failing");

        let mut buf = [0u8; 64];
        let mut n = 0usize;
        let err = pgp_encrypt_reader_read_blocking(er_h, buf.as_mut_ptr(), buf.len(), &mut n);
        assert!(!err.is_success(), "failing plaintext reader must surface");
        crate::interop_memory_free(err.message.cast_mut().cast());

        pgp_encrypt_reader_destroy(er_h);
        pgp_key_destroy(pub_h);
    }
}

#[test]
fn ffi_pgp_encrypt_reader_failing_plaintext_async_read_reports_error() {
    unsafe {
        let pub_h = pub_key_handle();
        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let ep = enc_params(&enc_keys, &sign_keys);
        let mut er_h = std::ptr::null_mut();
        pgp_encrypt_reader_open(
            &ep,
            make_failing_reader(),
            ForeignWriter::default(),
            ForeignWriter::default(),
            1,
            None,
            &mut er_h,
        )
        .abort_if_fail("er_open failing");

        let shared = new_async_state();
        let ctx_ptr = &*shared as *const _ as *mut c_void;
        let mut buf = vec![0u8; 64];
        pgp_encrypt_reader_read_async(er_h, buf.as_mut_ptr(), buf.len(), ctx_ptr, Some(async_cb))
            .abort_if_fail("er_read_async");

        let (bytes, error) = wait_done(&shared);
        assert!(error, "async completion must carry the reader failure");
        assert_eq!(bytes, 0);

        pgp_encrypt_reader_destroy(er_h);
        pgp_key_destroy(pub_h);
    }
}

#[test]
fn ffi_pgp_encrypt_reader_zero_length_blocking_read_returns_zero() {
    unsafe {
        let pub_h = pub_key_handle();
        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let ep = enc_params(&enc_keys, &sign_keys);
        let (pt_reader, _pt_state) = make_reader(PLAIN_TEXT.to_vec());
        let mut er_h = std::ptr::null_mut();
        pgp_encrypt_reader_open(
            &ep,
            pt_reader,
            ForeignWriter::default(),
            ForeignWriter::default(),
            1,
            None,
            &mut er_h,
        )
        .abort_if_fail("er_open");

        let mut buf = [0u8; 1];
        let mut n = 7usize;
        pgp_encrypt_reader_read_blocking(er_h, buf.as_mut_ptr(), 0, &mut n)
            .abort_if_fail("zero-length read");
        assert_eq!(n, 0);

        pgp_encrypt_reader_destroy(er_h);
        pgp_key_destroy(pub_h);
    }
}

// The worker is dispatched lazily on the first read; destroying an unread handle must reclaim
// the never-dispatched task (and its owned keys/callbacks) without running it or hanging.
#[test]
fn ffi_pgp_encrypt_reader_destroy_without_read_does_not_run_worker() {
    unsafe {
        let pub_h = pub_key_handle();
        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let ep = enc_params(&enc_keys, &sign_keys);
        let (pt_reader, _pt_state) = make_reader(PLAIN_TEXT.to_vec());
        let mut er_h = std::ptr::null_mut();
        pgp_encrypt_reader_open(
            &ep,
            pt_reader,
            ForeignWriter::default(),
            ForeignWriter::default(),
            1,
            None,
            &mut er_h,
        )
        .abort_if_fail("er_open");

        pgp_encrypt_reader_destroy(er_h);
        pgp_key_destroy(pub_h);
    }
}

#[test]
fn ffi_pgp_encrypt_reader_null_buffer_blocking_read_fails() {
    unsafe {
        let pub_h = pub_key_handle();
        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let ep = enc_params(&enc_keys, &sign_keys);
        let (pt_reader, _pt_state) = make_reader(PLAIN_TEXT.to_vec());
        let mut er_h = std::ptr::null_mut();
        pgp_encrypt_reader_open(
            &ep,
            pt_reader,
            ForeignWriter::default(),
            ForeignWriter::default(),
            1,
            None,
            &mut er_h,
        )
        .abort_if_fail("er_open");

        let mut n = 0usize;
        let err = pgp_encrypt_reader_read_blocking(er_h, std::ptr::null_mut(), 16, &mut n);
        assert!(!err.is_success(), "null buffer must be rejected");
        crate::interop_memory_free(err.message.cast_mut().cast());

        pgp_encrypt_reader_destroy(er_h);
        pgp_key_destroy(pub_h);
    }
}

#[test]
fn ffi_pgp_encrypt_reader_read_async_null_arguments_fail() {
    unsafe {
        let pub_h = pub_key_handle();
        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let ep = enc_params(&enc_keys, &sign_keys);
        let (pt_reader, _pt_state) = make_reader(PLAIN_TEXT.to_vec());
        let mut er_h = std::ptr::null_mut();
        pgp_encrypt_reader_open(
            &ep,
            pt_reader,
            ForeignWriter::default(),
            ForeignWriter::default(),
            1,
            None,
            &mut er_h,
        )
        .abort_if_fail("er_open");

        let mut buf = [0u8; 16];
        let err = pgp_encrypt_reader_read_async(
            er_h,
            buf.as_mut_ptr(),
            buf.len(),
            std::ptr::null_mut(),
            None,
        );
        assert!(!err.is_success(), "null callback must be rejected");
        crate::interop_memory_free(err.message.cast_mut().cast());

        let err = pgp_encrypt_reader_read_async(
            er_h,
            std::ptr::null_mut(),
            16,
            std::ptr::null_mut(),
            Some(async_cb),
        );
        assert!(!err.is_success(), "null buffer must be rejected");
        crate::interop_memory_free(err.message.cast_mut().cast());

        pgp_encrypt_reader_destroy(er_h);
        pgp_key_destroy(pub_h);
    }
}

// Runs the worker through an accepting host dispatcher — the same contract the C# ThreadPool
// implements — instead of the crate's fallback thread.
#[test]
fn ffi_pgp_encrypt_reader_round_trip_via_host_dispatcher() {
    unsafe {
        let pub_h = pub_key_handle();
        let priv_h = priv_key_handle();
        let enc_keys = [pub_h];
        let sign_keys: [*mut PgpKey; 0] = [];
        let ep = enc_params(&enc_keys, &sign_keys);
        let (pt_reader, _pt_state) = make_reader(PLAIN_TEXT.to_vec());
        let mut er_h = std::ptr::null_mut();
        pgp_encrypt_reader_open(
            &ep,
            pt_reader,
            ForeignWriter::default(),
            ForeignWriter::default(),
            1,
            Some(accepting_dispatcher),
            &mut er_h,
        )
        .abort_if_fail("er_open dispatched");

        let ciphertext = drain_encrypt_reader(er_h);
        assert!(!ciphertext.is_empty());
        pgp_encrypt_reader_destroy(er_h);

        decrypt_expecting(priv_h, &ciphertext, 1, PLAIN_TEXT);
        pgp_key_destroy(pub_h);
        pgp_key_destroy(priv_h);
    }
}
