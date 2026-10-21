use std::sync::Mutex;

use crate::interop::{InteropError, UnsafePtr, catch_error, copy_to_host_buffer};
use crate::pgp::keys::PgpKey;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use proton_rpgp::{DataEncoding, PublicKey};
use proton_srp::{
    RawSRPModulus, SRPAuth, SRPProof, ServerClientProof, ServerClientVerifier, ServerInteraction,
    ServerInteractionState, SrpHashVersion, mailbox_password_hash,
};
use zeroize::Zeroizing;
pub(crate) mod client;
pub(crate) mod server;

#[repr(C)]
pub(crate) struct ClientCreationParameters {
    username_len: usize,
    password_len: usize,
    salt_len: usize,
    signed_modulus_len: usize,
    username: *const u8,
    password: *const u8,
    salt: *const u8,
    signed_modulus: *const u8,
}

#[repr(C)]
pub(crate) struct ServerCreationParameters {
    modulus_len: usize,
    verifier_len: usize,
    modulus: *const u8,
    verifier: *const u8,
    bit_length: i32,
}

#[repr(C)]
pub(crate) struct ClientHandshakeBuffers {
    proof_buffer_len: usize,
    ephemeral_buffer_len: usize,
    proof_buffer: *mut u8,
    ephemeral_buffer: *mut u8,
}

pub(crate) struct SrpAuth {
    username: String,
    password: Zeroizing<String>,
    salt_b64: String,
    signed_modulus: String,
}

pub(crate) struct SrpClientHandshake {
    proof: SRPProof,
}

pub(crate) struct SrpServer {
    interaction: Mutex<ServerInteraction>,
}
fn verification_key_from_ptr(ptr: *const PgpKey) -> Result<&'static PublicKey, String> {
    Ok(UnsafePtr::as_ref(ptr)?.public_ref())
}
