//! Streaming between an FFI handle and its worker thread: the host-facing [`WriterHandle`] and the
//! constructor that wires a job onto a dispatched worker.
//! The unsafe zero-copy transport itself lives in [`chunk`].
//!
//! Only the write path (host pushes, worker consumes) uses a dispatched worker; the read paths
//! (decrypt/verify streams) serve reads synchronously on the calling host thread and live in
//! [`crate::pgp::reader`].

pub(crate) mod chunk;

use std::ffi::c_void;
use std::sync::mpsc::{SyncSender, sync_channel};

use crate::interop::catch_panic;
use crate::worker::{HostWorkDispatcherFn, WorkerLifecycle};
use chunk::{ChannelReader, ChunkProducer, chunk_channel};

pub(crate) struct WriterHandle {
    // `Option` so teardown can drop the producer — and with it the data channel's sender — *before*
    // waiting on the worker. The ack protocol parks the worker until the consumer acks, so closing
    // the channel first is what lets the worker finish instead of hanging. See [`ChunkProducer`].
    producer: Option<ChunkProducer>,
    worker: WorkerLifecycle<()>,
}

impl WriterHandle {
    pub(crate) fn write(&mut self, data: &[u8]) -> Result<usize, String> {
        let Some(producer) = &self.producer else {
            return Err("writer is closed".to_string());
        };
        producer.send(data)?;
        Ok(data.len())
    }

    pub(crate) fn close(&mut self) -> Result<(), String> {
        // Drop the producer before waiting: the worker parks on the ack protocol, so closing the
        // channel first is what lets `finish` receive the completion. `finish` is a no-op after the
        // first call, so an explicit close() followed by the `Drop` below is safe.
        self.producer = None;
        self.worker.finish().unwrap_or(Ok(()))
    }
}

impl Drop for WriterHandle {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

struct WriterWorkerContext<F> {
    reader: ChannelReader,
    completion: SyncSender<Result<(), String>>,
    job: F,
}

unsafe extern "C" fn writer_worker_entry<F>(args: *mut c_void)
where
    F: FnOnce(&mut ChannelReader) -> Result<(), String> + Send,
{
    // `args` is always `Box::into_raw` of a (non-ZST) context — never null.
    let WriterWorkerContext {
        mut reader,
        completion,
        job,
    } = *unsafe { Box::from_raw(args.cast::<WriterWorkerContext<F>>()) };
    // Catch panics: this fn is `extern "C"`, so a panic escaping the job (malformed input panicking
    // inside proton-rpgp, or a host callback) would abort the process. Convert it to an error
    // delivered through the channel/completion, like the non-streaming paths do.
    //
    // The job — and with it its captured host callbacks and owned inputs — is consumed inside
    // `catch_panic`, so everything host-facing is dropped before the completion is sent: the
    // completion is the teardown synchronization point (see [`WorkerLifecycle`]).
    let result = catch_panic(|| job(&mut reader));

    // On failure ack the in-flight chunk with the error so a parked `WriterHandle::write` surfaces
    // the real cause instead of a generic disconnect.
    if let Err(message) = &result {
        reader.fail(message.clone());
    }

    let _ = completion.send(result);
}

pub(crate) fn spawn_write_worker<F>(
    work_dispatcher: Option<HostWorkDispatcherFn>,
    worker: F,
) -> WriterHandle
where
    F: FnOnce(&mut ChannelReader) -> Result<(), String> + Send + 'static,
{
    let (producer, consumer) = chunk_channel();
    let (completion, completion_receiver) = sync_channel(1);
    let ctx = Box::new(WriterWorkerContext {
        reader: ChannelReader::new(consumer),
        completion,
        job: worker,
    });
    let mut lifecycle = WorkerLifecycle::pending(
        writer_worker_entry::<F>,
        ctx,
        work_dispatcher,
        completion_receiver,
        "writer",
    );
    lifecycle.ensure_started();

    WriterHandle {
        producer: Some(producer),
        worker: lifecycle,
    }
}

#[cfg(test)]
mod tests;
