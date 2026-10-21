use std::ffi::c_char;

pub(crate) mod armor;
pub(crate) mod decrypt;
pub(crate) mod encrypt;
pub(crate) mod keys;
pub(crate) mod message;
pub(crate) mod reader;
pub(crate) mod sign;
pub(crate) mod verify;

use crate::interop::{
    ForeignReader, ForeignWriter, FromId, InteropError, ToId, UnsafePtr, catch_error, malloc_bytes,
    malloc_c_string,
};
use crate::worker::HostWorkDispatcherFn;
pub(crate) use encrypt::EncryptionSettings;
use proton_rpgp::{
    AsPublicKeyRef, CheckUnixTime, DEFAULT_PROFILE, DataEncoding, Decryptor, EncryptedMessage,
    Encryptor, KeyGenerationType, KeyGenerator, KeyLock, LockedPrivateKey, PrivateKey, Profile,
    PublicKey, SessionKey, SignatureContext, Signer, UnixTime, VerificationContext,
    VerificationResult, Verifier,
    pgp::{armor::BlockType, crypto::sym::SymmetricKeyAlgorithm},
};

pub(crate) const AEAD_PROFILE_ID: u8 = 1;

pub(crate) use crate::stream::{WriterHandle, spawn_write_worker};

/// Streaming reader handle used by the PGP decrypt/verify paths; serves reads synchronously on
/// the calling host thread (see [`reader`]).
pub(crate) use reader::{ReaderHandle, ReaderJob};

/// Out-struct shared by the decrypt/verify entry points: plaintext is streamed into
/// `plaintext_buffer` and the verification result (when produced) is handed over as a fresh
/// handle.
#[repr(C)]
pub struct PlaintextResult {
    pub has_verification_result: bool,
    pub verification_result: *mut VerificationResult,
    pub plaintext_buffer: ForeignWriter,
}

impl FromId for Profile {
    type Output = Profile;

    fn from_id(value: u8) -> Self::Output {
        if value == AEAD_PROFILE_ID {
            proton_rpgp::HAZARD_AEAD_PROFILE.clone()
        } else {
            proton_rpgp::DEFAULT_PROFILE.clone()
        }
    }
}

impl FromId for DataEncoding {
    type Output = Result<DataEncoding, String>;

    fn from_id(value: u8) -> Self::Output {
        match value {
            0 => Ok(DataEncoding::Armored),
            1 => Ok(DataEncoding::Unarmored),
            2 => Ok(DataEncoding::Auto),
            _ => Err("Invalid data encoding".to_string()),
        }
    }
}

// Wrapper
pub(crate) fn check_unix_time(value: u64) -> CheckUnixTime {
    CheckUnixTime::enable(UnixTime::new(value))
}

#[cfg(test)]
pub mod tests;
