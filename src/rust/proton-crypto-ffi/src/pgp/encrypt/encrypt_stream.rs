//! C ABI for streaming encryption: one worker per handle runs the synchronous `proton-rpgp`
//! encrypt (started lazily on the first read) and writes ciphertext directly into the caller's
//! queued read requests — there is no intermediate pipe or relay task.
//!
//! That single-task shape is what makes the worker safe to run on a bounded host pool (the .NET
//! ThreadPool): every dispatched worker must be unblocked only by actors outside the pool. This
//! worker blocks only on host actions — the arrival of a read request, the synchronous plaintext
//! reader callback, or teardown closing the request queue — never on another dispatched task. A
//! relay task that pulls from the encrypt worker would violate this: it would occupy a pool
//! thread while the worker it waits on sits queued behind it, wedging the pool under concurrency
//! (the pool's blocking compensation cannot see native blocking).
//!
//! Plaintext is supplied as [`crate::interop::ForeignReader`] (synchronous `Read` callbacks). A
//! completion-based plaintext vtable was prototyped but hit Windows reverse-P/Invoke ABI issues
//! when invoked from the native encrypt worker thread; it can be reintroduced behind a separate
//! symbol once the host bridge is validated end-to-end.

use std::ffi::c_void;
use std::io::{BufReader, BufWriter, Read, Write};
use std::ptr;
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver, SyncSender, sync_channel};

use crate::interop::catch_error;
use crate::interop::{ForeignReader, ForeignWriter, InteropError, UnsafePtr, catch_panic};
use crate::pgp::encrypt::{
    EncryptionParameters, require_detached_signature_sink, write_detached_signature,
};
use crate::pgp::keys::{private_keys_from_keys, public_keys_from_keys};
use crate::pgp::{DataEncoding, EncryptionSettings, FromId};
use crate::worker::{HostWorkDispatcherFn, WorkerLifecycle};

use proton_rpgp::{PrivateKey, PublicKey, SessionKey, SignatureContext};

type PgpEncryptReaderReadCompleteFn =
    unsafe extern "C" fn(user_ctx: *mut c_void, bytes_read: usize, error: *const InteropError);

/// Boxed handle behind the `pgp_encrypt_reader_*` entry points: the request queue feeding the
/// encrypt worker. Blocking and async reads travel through the same queue and are served in
/// submission order by the worker.
pub(crate) struct EncryptReaderHandle {
    worker: Mutex<EncryptWorker>,
}

struct EncryptWorker {
    /// `Option` so teardown can drop the sender — closing the queue so the worker serves any
    /// still-queued reads and exits — *before* waiting on its completion (see
    /// [`WorkerLifecycle`]).
    sender: Option<mpsc::Sender<ReadRequest>>,
    lifecycle: WorkerLifecycle<()>,
}

/// One ciphertext read, queued to the encrypt worker. Pointers travel as `usize` so the request
/// is `Send`; the caller guarantees they stay valid until the request completes.
enum ReadRequest {
    /// `pgp_encrypt_reader_read_async`: `complete` fires on the worker.
    Async {
        buffer: usize,
        buffer_len: usize,
        user_ctx: usize,
        complete: PgpEncryptReaderReadCompleteFn,
    },
    /// `pgp_encrypt_reader_read_blocking`: the calling host thread is parked on `reply`.
    Blocking {
        buffer: usize,
        buffer_len: usize,
        reply: SyncSender<Result<usize, String>>,
    },
}

impl ReadRequest {
    /// Copies up to the request's capacity from `data` into the caller's buffer and completes
    /// the request with the count (or the marshalling error). Returns the number of bytes
    /// consumed from `data` — 0 for zero-length requests and failed marshalling, so the caller
    /// moves on to the next request with the same data.
    fn serve(self, data: &[u8]) -> usize {
        let (buffer, buffer_len) = match &self {
            Self::Async {
                buffer, buffer_len, ..
            }
            | Self::Blocking {
                buffer, buffer_len, ..
            } => (*buffer as *mut u8, *buffer_len),
        };
        let len = buffer_len.min(data.len());

        // Report a buffer-marshalling failure through the completion like any read error, rather
        // than killing the worker — which would leave later queued requests unanswered.
        let result = UnsafePtr::get_slice_mut(buffer, buffer_len).map(|buf| {
            buf[..len].copy_from_slice(&data[..len]);
            len
        });
        let consumed = *result.as_ref().unwrap_or(&0);
        self.complete(result);
        consumed
    }

    /// Delivers the read's outcome: fires the async callback or wakes the parked blocking caller.
    fn complete(self, result: Result<usize, String>) {
        match self {
            Self::Async {
                user_ctx, complete, ..
            } => finish_async_read(complete, user_ctx as *mut c_void, result),
            Self::Blocking { reply, .. } => {
                let _ = reply.send(result);
            }
        }
    }
}

/// The `InteropError` struct itself is only valid for the duration of the call, but its message
/// follows the same ownership contract as every other `InteropError` in this crate: it is
/// heap-allocated and the host must release it with `interop_memory_free`.
fn finish_async_read(
    complete: PgpEncryptReaderReadCompleteFn,
    user_ctx: *mut c_void,
    read_result: Result<usize, String>,
) {
    match read_result {
        Ok(bytes_read) => unsafe { complete(user_ctx, bytes_read, ptr::null()) },
        Err(message) => {
            let error = InteropError::failure(message);
            unsafe { complete(user_ctx, 0, ptr::addr_of!(error)) };
        }
    }
}

/// The encrypt worker's ciphertext sink: each write parks until the host queues a read request,
/// then copies directly into that request's buffer and completes it. The park is released only by
/// host calls (`pgp_encrypt_reader_read_*`) or by teardown closing the queue — never by another
/// dispatched task — which is what makes the worker safe on a bounded host pool (see the module
/// docs).
struct RequestSink<'a> {
    requests: &'a Receiver<ReadRequest>,
}

impl Write for RequestSink<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        loop {
            let request = self.requests.recv().map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "encrypt reader closed")
            })?;
            match request.serve(data) {
                // Zero-length request (completed with 0, in order) or failed marshalling: no
                // bytes consumed, serve the same data to the next request.
                0 => {}
                consumed => return Ok(consumed),
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl EncryptReaderHandle {
    fn new(
        plaintext: ForeignReader,
        params: StreamingEncryptParams,
        work_dispatcher: Option<HostWorkDispatcherFn>,
    ) -> Self {
        let (sender, requests) = mpsc::channel();
        let (completion, completion_receiver) = sync_channel(1);
        let ctx = Box::new(EncryptWorkerContext {
            plaintext,
            params,
            requests,
            completion,
        });
        Self {
            worker: Mutex::new(EncryptWorker {
                sender: Some(sender),
                lifecycle: WorkerLifecycle::pending(
                    encrypt_worker_entry,
                    ctx,
                    work_dispatcher,
                    completion_receiver,
                    "encrypt",
                ),
            }),
        }
    }

    /// Queues a read, dispatching the worker on first use. Lazy: the worker — and its pull on the
    /// host plaintext reader and side writers — must not start until the consumer first asks for
    /// ciphertext.
    fn queue_read(&self, request: ReadRequest) -> Result<(), String> {
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| "encrypt reader lock poisoned".to_string())?;
        worker.lifecycle.ensure_started();
        worker
            .sender
            .as_ref()
            .ok_or_else(|| "encrypt reader is shut down".to_string())?
            .send(request)
            .map_err(|_| "encrypt worker exited".to_string())
    }

    fn read_blocking(&self, buffer: *mut u8, buffer_len: usize) -> Result<usize, String> {
        if buffer_len == 0 {
            return Ok(0);
        }
        let (reply, response) = sync_channel(1);
        self.queue_read(ReadRequest::Blocking {
            buffer: buffer as usize,
            buffer_len,
            reply,
        })?;
        response
            .recv()
            .map_err(|_| "encrypt worker exited without completing the read".to_string())?
    }
}

impl Drop for EncryptReaderHandle {
    fn drop(&mut self) {
        let worker = self
            .worker
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Close the queue before finishing: the worker serves any still-queued reads (their
        // callbacks fire) and only then exits and sends the completion `finish` waits for.
        worker.sender = None;
        let _ = worker.lifecycle.finish();
    }
}

/// Dispatch context for the encrypt worker: the owned encryption job plus its request queue and
/// oneshot completion.
struct EncryptWorkerContext {
    plaintext: ForeignReader,
    params: StreamingEncryptParams,
    requests: Receiver<ReadRequest>,
    completion: SyncSender<Result<(), String>>,
}

unsafe extern "C" fn encrypt_worker_entry(args: *mut c_void) {
    // `args` is always `Box::into_raw` of a (non-ZST) context — never null.
    let EncryptWorkerContext {
        plaintext,
        params,
        requests,
        completion,
    } = *unsafe { Box::from_raw(args.cast::<EncryptWorkerContext>()) };

    // Catch panics: this fn is `extern "C"`, so a panic escaping the job (malformed input
    // panicking inside proton-rpgp, or a host callback) would abort the process. Convert it to an
    // error delivered through the pending reads and the completion, like the non-streaming paths.
    //
    // The job's host-facing captures (`plaintext`, `params` with its side writers) move into the
    // closure so they are dropped — even on unwind — before the completion is sent: the
    // completion is the teardown synchronization point (see [`WorkerLifecycle`]).
    let requests_ref = &requests;
    let result = catch_panic(move || {
        let mut params = params;
        let mut plaintext = BufReader::new(plaintext);
        // Coalesce the encryptor's small writes — armored output arrives one 65-byte line at a
        // time, unarmored interleaves 1-byte framing writes between AEAD chunks — so each read
        // request costs one host round trip per buffer, not per write. Writes at or above the
        // `BufWriter` capacity bypass its buffer entirely, so bulk AEAD chunks still land in the
        // caller's buffer with a single copy.
        let mut cipher_writer = BufWriter::new(RequestSink {
            requests: requests_ref,
        });
        let result = fun_encrypt_stream(&mut params, &mut plaintext, &mut cipher_writer)
            .and_then(|()| cipher_writer.flush().map_err(|error| error.to_string()));
        // On failure, discard any buffered ciphertext instead of letting flush-on-drop park the
        // worker on the request queue just to deliver bytes from a failed stream.
        let _ = cipher_writer.into_parts();
        result
    });

    // Serve reads arriving after the stream ended — EOF on success, the error otherwise — until
    // teardown closes the queue. Every queued request's callback fires before the completion is
    // sent, so no read is left unanswered once `finish` returns.
    while let Ok(request) = requests.recv() {
        request.complete(match &result {
            Ok(()) => Ok(0),
            Err(message) => Err(message.clone()),
        });
    }

    let _ = completion.send(result);
}

fn build_streaming_encrypt_params(
    params: &EncryptionParameters,
    encoding: u8,
    signature_writer: ForeignWriter,
    key_packet_writer: ForeignWriter,
) -> Result<StreamingEncryptParams, String> {
    let keys = UnsafePtr::get_handle_slice(params.encryption_keys, params.encryption_keys_len)?;
    let encryption_keys = public_keys_from_keys(keys)
        .cloned()
        .collect::<Vec<PublicKey>>();
    let signing_keys = private_keys_from_keys(UnsafePtr::get_handle_slice(
        params.signing_keys,
        params.signing_keys_len,
    )?)
    .map(|key| key.cloned())
    .collect::<Result<Vec<_>, _>>()?;
    let password = UnsafePtr::get_slice(params.password, params.password_len)?;
    let password = (!password.is_empty()).then_some(password.to_vec());
    let session_key = UnsafePtr::maybe_ref(params.session_key, params.has_session_key)?;
    let signing_context = UnsafePtr::maybe_ref(params.signing_context, params.has_signing_context)?;
    Ok(StreamingEncryptParams {
        encryption_keys,
        signing_keys,
        password,
        session_key: session_key.cloned(),
        signing_context: signing_context.cloned(),
        settings: params.into(),
        encoding,
        signature_writer,
        key_packet_writer,
    })
}

/// Releases a streaming encrypt-reader handle created by `pgp_encrypt_reader_open`.
///
/// Any reads still queued via `pgp_encrypt_reader_read_async` are completed (their callbacks
/// invoked) before the handle is released.
///
/// # Safety
/// `reader` must be a live handle from `pgp_encrypt_reader_open` and must not be used after this
/// call; buffers of outstanding async reads must stay valid until their `complete` callbacks run.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_encrypt_reader_destroy(reader: *mut EncryptReaderHandle) {
    UnsafePtr::drop_raw(reader);
}

/// Owned encryption inputs and side writers for a streaming encrypt operation. A non-null
/// `key_packet_writer` enables key-packet/data-packet splitting.
struct StreamingEncryptParams {
    encryption_keys: Vec<PublicKey>,
    signing_keys: Vec<PrivateKey>,
    password: Option<Vec<u8>>,
    session_key: Option<SessionKey>,
    signing_context: Option<SignatureContext>,
    settings: EncryptionSettings,
    encoding: u8,
    signature_writer: ForeignWriter,
    key_packet_writer: ForeignWriter,
}

fn fun_encrypt_stream(
    job: &mut StreamingEncryptParams,
    reader: &mut impl Read,
    mut cipher_writer: impl Write,
) -> Result<(), String> {
    let password = job.password.as_deref();
    let session_key = job.session_key.as_ref();
    let signing_context = job.signing_context.as_ref();
    let encryptor = job.settings.build_encryptor(
        &job.encryption_keys,
        &job.signing_keys,
        session_key,
        signing_context,
        password,
    );

    if !job.key_packet_writer.is_null() {
        let (key_packets, info) = encryptor
            .encrypt_stream_split(reader, &mut cipher_writer)
            .map_err(|error| error.to_string())?;
        job.key_packet_writer
            .write_all(&key_packets)
            .map_err(|error| error.to_string())?;

        if job.settings.detached_sig {
            require_detached_signature_sink(job.signature_writer, !job.signing_keys.is_empty())?;
            // Split output is raw packets, so the detached signature is unarmored too.
            write_detached_signature(job.signature_writer, info.detached_signature(), false)?;
        }
        return Ok(());
    }

    let info = encryptor
        .encrypt_stream(
            reader,
            DataEncoding::from_id(job.encoding)?,
            &mut cipher_writer,
        )
        .map_err(|error| error.to_string())?;

    if job.settings.detached_sig {
        require_detached_signature_sink(job.signature_writer, !job.signing_keys.is_empty())?;
        // Armored for everything except explicit unarmored output, matching `pgp_encrypt`
        // (encoding ids: 0 armored, 1 unarmored, other auto).
        write_detached_signature(
            job.signature_writer,
            info.detached_signature(),
            job.encoding != 1,
        )?;
    }

    Ok(())
}

/// Opens a streaming encrypt-reader and writes its handle into `*out_handle`.
///
/// Builds the encrypt worker from `parameters`, drawing plaintext from `plaintext_reader`.
/// `signature_writer` and `key_packet_writer` are optional sinks (pass null to omit); supplying a
/// non-null `key_packet_writer` enables key-packet/data-packet splitting. `encoding` selects the
/// ciphertext output encoding and the optional `work_dispatcher` runs the encrypt worker.
/// The resulting handle is written into `*out_handle` (release with `pgp_encrypt_reader_destroy`).
///
/// # Safety
/// `parameters` must be a valid non-null pointer to an initialized `EncryptionParameters` whose
/// embedded handles and pointers are valid; the `plaintext_reader`/`signature_writer`/
/// `key_packet_writer` host callbacks must stay valid until the handle is destroyed; `out_handle`
/// must be a non-null, writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_encrypt_reader_open(
    parameters: *const EncryptionParameters,
    plaintext_reader: ForeignReader,
    signature_writer: ForeignWriter,
    key_packet_writer: ForeignWriter,
    encoding: u8,
    work_dispatcher: Option<HostWorkDispatcherFn>,
    out_handle: *mut *mut EncryptReaderHandle,
) -> InteropError {
    catch_error(|| {
        let params = UnsafePtr::as_ref(parameters)?;
        let params =
            build_streaming_encrypt_params(params, encoding, signature_writer, key_packet_writer)?;

        *UnsafePtr::ref_mut(out_handle)? = UnsafePtr::new_raw(EncryptReaderHandle::new(
            plaintext_reader,
            params,
            work_dispatcher,
        ));
        Ok(())
    })
}

/// Blocking ciphertext read.
///
/// Queues the read like `pgp_encrypt_reader_read_async` — served by the worker in submission
/// order with any queued async reads — and parks the calling thread until it completes. Reads
/// ciphertext into `buffer` (up to `buffer_len` bytes) and writes the count into `*data_read`
/// (0 indicates end of stream).
///
/// # Safety
/// `reader` must be a live handle from `pgp_encrypt_reader_open`; `buffer` must be writable for
/// `buffer_len` bytes (or null when `buffer_len == 0`); `data_read` must be a non-null, writable
/// `*mut usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_encrypt_reader_read_blocking(
    reader: *const EncryptReaderHandle,
    buffer: *mut u8,
    buffer_len: usize,
    data_read: *mut usize,
) -> InteropError {
    catch_error(|| {
        let data_read = UnsafePtr::ref_mut(data_read)?;
        *data_read = 0;
        if buffer_len > 0 && buffer.is_null() {
            return Err("buffer is null".to_string());
        }
        *data_read = UnsafePtr::as_ref(reader)?.read_blocking(buffer, buffer_len)?;
        Ok(())
    })
}

/// Queues a ciphertext read on the handle's encrypt worker and returns immediately.
///
/// `complete` is invoked on that worker when the read finishes (or fails), receiving `user_ctx`,
/// the number of bytes read, and an `*const InteropError` (null on success; on failure the struct
/// is valid only for the callback but its message is heap-allocated and must be released with
/// `interop_memory_free`). Queued reads complete in submission order. Until `complete` runs,
/// `buffer` must remain valid and writable for `buffer_len` bytes. A null `complete` callback is
/// rejected with a failure error.
///
/// # Safety
/// `reader` must be a live handle from `pgp_encrypt_reader_open`; `buffer` must stay valid,
/// writable, and pinned for `buffer_len` bytes until `complete` runs on the worker thread;
/// `complete` must be a valid callback and `user_ctx` is passed through to it unchanged.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_encrypt_reader_read_async(
    reader: *const EncryptReaderHandle,
    buffer: *mut u8,
    buffer_len: usize,
    user_ctx: *mut c_void,
    complete: Option<PgpEncryptReaderReadCompleteFn>,
) -> InteropError {
    catch_error(|| {
        let Some(complete) = complete else {
            return Err("pgp_encrypt_reader_read_async: complete callback is null".to_string());
        };
        if buffer_len > 0 && buffer.is_null() {
            return Err("buffer is null".to_string());
        }
        // A zero-length read is queued like any other so it completes on the worker thread, in
        // submission order (the worker turns the empty buffer into a 0-byte completion).
        UnsafePtr::as_ref(reader)?.queue_read(ReadRequest::Async {
            buffer: buffer as usize,
            buffer_len,
            user_ctx: user_ctx as usize,
            complete,
        })
    })
}

#[cfg(test)]
mod tests;
