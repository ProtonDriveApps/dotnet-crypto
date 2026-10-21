use base64::{Engine, engine::general_purpose::STANDARD as B64};

use crate::interop::{ForeignReader, ForeignWriter, InteropError};
use crate::pgp::PlaintextResult;
use crate::pgp::ReaderHandle;
use crate::pgp::keys::{PgpKey, pgp_private_key_import_unlock, pgp_public_key_import};
use crate::pgp::reader::pgp_reader_read;
pub(crate) const PASSPHRASE: &[u8] =
    include_str!("../../../../tests/data/pgp/passphrase.txt").as_bytes();
pub(crate) const PLAIN_TEXT: &[u8] =
    include_str!("../../../../tests/data/pgp/plain_text.txt").as_bytes();

pub(crate) const SRP_USERNAME: &str = include_str!("../../../../tests/data/srp/username.txt");
pub(crate) const SRP_PASSWORD: &str = include_str!("../../../../tests/data/srp/password.txt");
pub(crate) const SRP_DERIVED_PASSWORD: &str =
    include_str!("../../../../tests/data/srp/derived_password.txt");

pub(crate) const SRP_SALT_B64: &str = include_str!("../../../../tests/data/srp/salt.b64");
pub(crate) const SRP_PASSWORD_HASHING_SALT_B64: &str =
    include_str!("../../../../tests/data/srp/password_hashing_salt.b64");
pub(crate) const SRP_MODULUS_B64: &str = include_str!("../../../../tests/data/srp/modulus.b64");
pub(crate) const SRP_VERIFIER_B64: &str = include_str!("../../../../tests/data/srp/verifier.b64");
pub(crate) const SRP_SERVER_SECRET_B64: &str =
    include_str!("../../../../tests/data/srp/server_secret.b64");
pub(crate) const SRP_SERVER_EPHEMERAL_B64: &str =
    include_str!("../../../../tests/data/srp/server_ephemeral.b64");

pub(crate) const SRP_SIGNED_MODULUS: &str =
    include_str!("../../../../tests/data/srp/signed_modulus.asc");

pub(crate) const ARMORED_LOCKED_PRIVATE_KEY_V4: &str =
    include_str!("../../../../tests/data/pgp/locked_private_key_v4.asc");
pub(crate) const ARMORED_LOCKED_PRIVATE_KEY_V6: &str =
    include_str!("../../../../tests/data/pgp/locked_private_key_v6.asc");
pub(crate) const ARMORED_PUBLIC_KEY_V4: &str =
    include_str!("../../../../tests/data/pgp/public_key_v4.asc");
pub(crate) const ARMORED_PUBLIC_KEY_V6: &str =
    include_str!("../../../../tests/data/pgp/public_key_v6.asc");
pub(crate) const KEY_BASED_ARMORED_UNSIGNED_MESSAGE: &str =
    include_str!("../../../../tests/data/pgp/encrypted_message_unsigned.asc");
pub(crate) const ARMORED_SIGNED_MESSAGE: &str =
    include_str!("../../../../tests/data/pgp/plain_message_signed.asc");

pub(crate) fn decode_b64(s: &str) -> Vec<u8> {
    B64.decode(s.trim())
        .expect("test data should be valid base64")
}

pub(crate) fn signature_v4() -> Vec<u8> {
    decode_b64(include_str!("../../../../tests/data/pgp/signature_v4.b64"))
}
pub(crate) fn signature_v4_invalid() -> Vec<u8> {
    decode_b64(include_str!(
        "../../../../tests/data/pgp/signature_v4_invalid.b64"
    ))
}
pub(crate) fn key_packet_v4() -> Vec<u8> {
    decode_b64(include_str!("../../../../tests/data/pgp/key_packet_v4.b64"))
}
pub(crate) fn data_packet() -> Vec<u8> {
    decode_b64(include_str!("../../../../tests/data/pgp/data_packet.b64"))
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}
pub(crate) fn session_key_token() -> Vec<u8> {
    decode_b64(include_str!(
        "../../../../tests/data/pgp/session_key_token.b64"
    ))
}

// ── ForeignWriter backed by Vec<u8> ──────────────────────────────────────────

pub(crate) unsafe extern "C" fn vec_write_fn(ptr: usize, data: *const u8, len: usize) -> i64 {
    unsafe {
        (*(ptr as *mut Vec<u8>)).extend_from_slice(std::slice::from_raw_parts(data, len));
        len as i64
    }
}

pub(crate) fn vec_writer(buf: &mut Vec<u8>) -> ForeignWriter {
    ForeignWriter {
        sink: buf as *mut Vec<u8> as usize,
        write: Some(vec_write_fn),
    }
}

// ── ForeignReader backed by &[u8] ─────────────────────────────────────────────

pub(crate) struct SliceReader {
    pub data: Vec<u8>,
    pub pos: usize,
}

pub(crate) unsafe extern "C" fn slice_read_fn(
    ptr: usize,
    buf: *mut u8,
    len: usize,
    err: *mut i32,
) -> i64 {
    unsafe {
        let s = &mut *(ptr as *mut SliceReader);
        *err = 0;
        if s.pos >= s.data.len() {
            *err = 1;
            return 0;
        }
        let n = (s.data.len() - s.pos).min(len);
        std::ptr::copy_nonoverlapping(s.data[s.pos..].as_ptr(), buf, n);
        s.pos += n;
        n as i64
    }
}

pub(crate) fn make_reader(data: Vec<u8>) -> (ForeignReader, Box<SliceReader>) {
    let mut state = Box::new(SliceReader { data, pos: 0 });
    let reader = ForeignReader {
        ptr: &mut *state as *mut SliceReader as usize,
        read: Some(slice_read_fn),
    };
    (reader, state)
}

// ── ForeignReader that always fails ───────────────────────────────────────────

pub(crate) unsafe extern "C" fn failing_read_fn(
    _ptr: usize,
    _buf: *mut u8,
    _len: usize,
    err: *mut i32,
) -> i64 {
    unsafe { *err = -1 };
    0
}

pub(crate) fn make_failing_reader() -> ForeignReader {
    ForeignReader {
        ptr: 1,
        read: Some(failing_read_fn),
    }
}

// ── Host work dispatcher stub ─────────────────────────────────────────────────

/// Accepts every task and runs it asynchronously on its own thread — the host-dispatcher
/// contract the C# ThreadPool implements in production.
pub(crate) unsafe extern "C" fn accepting_dispatcher(task: crate::worker::Task) -> bool {
    let fun = task.fun;
    let args = task.args as usize;
    std::thread::spawn(move || unsafe { fun(args as *mut std::ffi::c_void) });
    true
}

// ── Drain a ReaderHandle via pgp_reader_read ──────────────────────────────────

pub(crate) fn drain_reader(handle: *mut ReaderHandle) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        let mut n = 0usize;
        unsafe { pgp_reader_read(handle, buf.as_mut_ptr(), buf.len(), &mut n) }
            .abort_if_fail("drain");
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    out
}

// ── PlaintextResult backed by Vec<u8> ────────────────────────────────────────

pub(crate) fn make_plaintext_result(buf: &mut Vec<u8>) -> PlaintextResult {
    PlaintextResult {
        has_verification_result: false,
        verification_result: std::ptr::null_mut(),
        plaintext_buffer: vec_writer(buf),
    }
}

// ── Key handle helpers ────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub(crate) enum KeyVersion {
    V4,
    V6,
}

impl KeyVersion {
    pub(crate) fn public_armored(self) -> &'static str {
        match self {
            Self::V4 => ARMORED_PUBLIC_KEY_V4,
            Self::V6 => ARMORED_PUBLIC_KEY_V6,
        }
    }

    pub(crate) fn private_armored(self) -> &'static str {
        match self {
            Self::V4 => ARMORED_LOCKED_PRIVATE_KEY_V4,
            Self::V6 => ARMORED_LOCKED_PRIVATE_KEY_V6,
        }
    }
}

pub(crate) fn pub_key_handle_v(version: KeyVersion) -> *mut PgpKey {
    let key = version.public_armored().as_bytes();
    let mut h = std::ptr::null_mut();
    unsafe { pgp_public_key_import(key.as_ptr(), key.len(), 0, &mut h) }
        .abort_if_fail("pub_key_handle");
    h
}

pub(crate) fn priv_key_handle_v(version: KeyVersion) -> *mut PgpKey {
    let key = version.private_armored().as_bytes();
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
        .abort_if_fail("priv_key_handle");
    }
    h
}

pub(crate) fn pub_key_handle() -> *mut PgpKey {
    pub_key_handle_v(KeyVersion::V4)
}

pub(crate) fn priv_key_handle() -> *mut PgpKey {
    priv_key_handle_v(KeyVersion::V4)
}
impl InteropError {
    pub(crate) fn is_success(&self) -> bool {
        self.message.is_null() && self.message_length == 0
    }
    pub fn abort_if_fail(&self, msg: &str) {
        if !self.is_success() {
            dbg!(self);
            eprintln!("{self}");
            panic!("{msg}");
        }
    }

    pub fn message_text(&self) -> &str {
        if self.message.is_null() || self.message_length <= 0 {
            return "<no message>";
        }
        let s = unsafe { std::slice::from_raw_parts(self.message, self.message_length as usize) };
        std::str::from_utf8(s).unwrap_or("<invalid UTF-8>")
    }
}

impl std::fmt::Display for InteropError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error: {}", self.message_text())
    }
}
