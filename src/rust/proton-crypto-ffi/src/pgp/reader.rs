//! The host-facing handle for streaming decrypt/verify readers, and its FFI entry points.
//!
//! Reads are served *synchronously on the calling host thread*: the handle owns an upstream
//! [`VerifyingReader`] and each `pgp_reader_read` pulls ciphertext through the host's input
//! callback on the same thread. No worker task is dispatched and nothing parks waiting for
//! another scheduled task, so a stream can never depend on host thread-pool growth to make
//! progress (see the encrypt-side module docs for the invariant; the previous worker+channel
//! design deadlocked bounded pools).
//!
//! The reader borrows the keys it verifies with for its whole lifetime
//! (`VerifyingReader<'a>` holds `&'a PublicKey`s), while the host may destroy its key handles
//! right after the stream is opened. The handle therefore owns *clones* of every input
//! ([`ReaderJob`]) and stores the reader alongside them in a [`self_cell`] — a self-referential
//! pair whose construction and drop order the library enforces, keeping this module free of
//! hand-written `unsafe`.

use std::io::Read;

use self_cell::self_cell;

use super::{
    InteropError, PrivateKey, PublicKey, SessionKey, UnsafePtr, VerificationContext,
    VerificationResult, catch_error,
};
use proton_rpgp::VerifyingReader;

/// The owned inputs a streaming reader borrows for its whole life: cloned keys and options,
/// so the host can free its own handles as soon as the stream is open. Unused fields stay at
/// their defaults (the verify-only path needs just the verification keys and context).
#[derive(Default)]
pub(crate) struct ReaderJob {
    pub(crate) decryption_keys: Vec<PrivateKey>,
    pub(crate) verification_keys: Vec<PublicKey>,
    pub(crate) session_key: Option<SessionKey>,
    pub(crate) verification_context: Option<VerificationContext>,
    pub(crate) password: Option<Vec<u8>>,
    pub(crate) detached_signature: Option<Vec<u8>>,
}

/// `Option` so [`ReaderHandle::take_result`] can move the reader out of the cell:
/// [`VerifyingReader::verification_result`] consumes the reader, and a `None` afterwards makes
/// further reads report end of stream instead of touching a finalized reader.
type OptionalVerifyingReader<'a> = Option<VerifyingReader<'a>>;

self_cell!(
    struct ReaderCell {
        owner: ReaderJob,

        #[not_covariant]
        dependent: OptionalVerifyingReader,
    }
);

/// Host-facing streaming reader: the owned inputs and the upstream reader borrowing them.
pub(crate) struct ReaderHandle {
    cell: ReaderCell,
}

impl ReaderHandle {
    /// Opens a stream: `open` builds the upstream reader from the borrowed job — constructing
    /// the decryptor/verifier and consuming any stream header — synchronously on the calling
    /// thread.
    pub(crate) fn try_new(
        job: ReaderJob,
        open: impl for<'a> FnOnce(&'a ReaderJob) -> Result<VerifyingReader<'a>, String>,
    ) -> Result<Self, String> {
        Ok(Self {
            cell: ReaderCell::try_new(job, |job| open(job).map(Some))?,
        })
    }

    /// Reads plaintext, pulling ciphertext through the host's input callback on this thread.
    /// `Ok(0)` signals end of stream — also after finalization, mirroring host `Stream`
    /// semantics where reads past the end are harmless.
    pub(crate) fn read(&mut self, buffer: &mut [u8]) -> Result<usize, String> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.cell
            .with_dependent_mut(|_job, reader| match reader.as_mut() {
                Some(reader) => reader.read(buffer).map_err(|error| error.to_string()),
                None => Ok(0),
            })
    }

    /// Finalizes the stream and hands over the verification result. Fails on a second call
    /// (the upstream reader is consumed by the first).
    pub(crate) fn take_result(&mut self) -> Result<VerificationResult, String> {
        self.cell.with_dependent_mut(|_job, reader| {
            reader
                .take()
                .map(VerifyingReader::verification_result)
                .ok_or_else(|| "reader has no verification result".to_string())
        })
    }
}

/// Reads decrypted/verified plaintext from a streaming reader handle.
///
/// Reads up to `buffer_len` bytes into `buffer` and writes the number produced into `*data_read`
/// (0 indicates end of stream). The read runs on the calling thread, pulling ciphertext through
/// the stream's host input callback, so it blocks for as long as that callback does.
///
/// # Safety
/// `ptr` must be a live reader handle from a decrypt/verify stream-open call; `buffer` must be
/// writable for `buffer_len` bytes (or null when `buffer_len == 0`); `data_read` must be a
/// non-null, writable `*mut usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_reader_read(
    ptr: *mut ReaderHandle,
    buffer: *mut u8,
    buffer_len: usize,
    data_read: *mut usize,
) -> InteropError {
    catch_error(|| {
        let data_read = UnsafePtr::ref_mut(data_read)?;
        *data_read = 0;
        let data = UnsafePtr::get_slice_mut(buffer, buffer_len)?;
        *data_read = UnsafePtr::ref_mut(ptr)?.read(data)?;
        Ok(())
    })
}

/// Finalizes the stream and writes a verification-result handle into `*out_verification_result`.
///
/// Takes the verification result from the reader identified by `ptr` and writes a fresh handle into
/// `*out_verification_result` (release with `pgp_verification_result_destroy`). Should be called
/// after the plaintext has been fully read; afterwards further reads report end of stream and a
/// second call fails.
///
/// # Safety
/// `ptr` must be a live reader handle from a verify stream-open call; `out_verification_result`
/// must be a non-null, writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_verification_reader_get_verify_result(
    ptr: *mut ReaderHandle,
    out_verification_result: *mut *mut VerificationResult,
) -> InteropError {
    catch_error(|| {
        let verification = UnsafePtr::ref_mut(ptr)?.take_result()?;
        *UnsafePtr::ref_mut(out_verification_result)? = UnsafePtr::new_raw(verification);
        Ok(())
    })
}

/// Releases a streaming reader handle.
///
/// A plain drop: there is no worker to wait for and no host callback is invoked, so this never
/// blocks — safe to call with the stream in any state, including mid-read teardown on a
/// saturated host pool.
///
/// # Safety
/// `ptr` must be a live reader handle from a decrypt/verify stream-open call and must not be used
/// after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_reader_destroy(ptr: *mut ReaderHandle) {
    UnsafePtr::drop_raw(ptr);
}
