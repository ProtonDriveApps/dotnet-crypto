//! The ack-based zero-copy chunk protocol: a producer lends a borrowed slice across a channel and
//! blocks until the consumer acknowledges it, so each streamed chunk crosses threads with exactly
//! one copy and no per-chunk allocation. A stream lives on one fixed channel pair (data forward,
//! acks back) created by [`chunk_channel`]. Every `unsafe impl Send` and raw-pointer borrow of the
//! streaming design lives in this file; the safety argument is the ack protocol described on
//! [`RawChunk`]. Used only by the write path ([`WriterHandle`](super::WriterHandle) →
//! [`ChannelReader`]); the read paths serve the host synchronously without crossing threads.

use std::io::Read;
use std::ptr;
use std::slice;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

// A borrowed slice transmitted across the channel boundary via ack-based ownership protocol.
// Safety invariant: the owner of the originating buffer must not modify or free it
// until the corresponding ack is received.
pub(crate) struct RawChunk {
    ptr: *const u8,
    len: usize,
}

// Safety: access to the pointed-to memory is serialised by the ack protocol.
unsafe impl Send for RawChunk {}

/// A streamed chunk to process, or the producer's terminal error. On the write path
/// (host → worker) the `Err` variant is never produced, since a consuming worker reports its
/// failure backwards through the ack instead.
pub(crate) type ChunkResult = Result<RawChunk, String>;

/// Creates the fixed channel pair a stream lives on — chunks forward, per-chunk acks back — and
/// returns the two halves. One pair per stream; nothing is allocated per chunk.
pub(crate) fn chunk_channel() -> (ChunkProducer, ChunkConsumer) {
    let (data_sender, data_receiver) = sync_channel(1);
    let (ack_sender, ack_receiver) = sync_channel(1);
    (
        ChunkProducer {
            data: data_sender,
            ack: ack_receiver,
        },
        ChunkConsumer {
            data: data_receiver,
            ack: ack_sender,
            current_ptr: ptr::null(),
            current_len: 0,
            current_offset: 0,
            in_flight: false,
        },
    )
}

/// Consumer half of the chunk channel: pulls borrowed chunks off the data channel, copies them
/// into the caller's buffer, and acks each chunk once it has been fully drained.
///
/// A chunk is borrowed (see [`RawChunk`]), so the holder of the originating buffer must not free
/// it until the ack is sent; that invariant is upheld by acking only on full consumption — or on
/// teardown, when dropping the whole consumer closes the ack channel and releases a parked
/// producer. Wrapped by [`ChannelReader`] (the worker's input adapter).
pub(crate) struct ChunkConsumer {
    data: Receiver<ChunkResult>,
    /// Sending half of the stream's single ack channel. At most one ack is ever pending (strict
    /// alternation with the producer), so `send` never blocks on the capacity-1 channel.
    ack: SyncSender<Result<(), String>>,
    current_ptr: *const u8,
    current_len: usize,
    current_offset: usize,
    /// Whether a chunk is currently borrowed — its producer parked waiting for the ack. Must be
    /// set in the same step that stores the cursor, and cleared exactly when the ack is sent.
    in_flight: bool,
}

// Safety: `current_ptr` borrows the producer's buffer only under the ack protocol — the same
// invariant that lets [`RawChunk`] cross the channel.
unsafe impl Send for ChunkConsumer {}

impl ChunkConsumer {
    /// Copies up to `buffer.len()` bytes from the stream into `buffer`, returning the number copied
    /// (0 = end of stream). Surfaces a producer's terminal error as `Err`.
    pub(crate) fn read(&mut self, buffer: &mut [u8]) -> Result<usize, String> {
        if buffer.is_empty() {
            return Ok(0);
        }

        loop {
            if self.current_offset < self.current_len {
                // Safety: the ack protocol ensures the producer's buffer remains alive until we ack.
                let src = unsafe {
                    slice::from_raw_parts(
                        self.current_ptr.add(self.current_offset),
                        self.current_len - self.current_offset,
                    )
                };
                let to_copy = src.len().min(buffer.len());
                buffer[..to_copy].copy_from_slice(&src[..to_copy]);
                self.current_offset += to_copy;
                if self.current_offset >= self.current_len {
                    self.finish_current(Ok(()));
                }
                return Ok(to_copy);
            }

            match self.data.recv() {
                Ok(Ok(chunk)) => {
                    self.current_ptr = chunk.ptr;
                    self.current_len = chunk.len;
                    self.current_offset = 0;
                    self.in_flight = true;
                }
                Ok(Err(message)) => return Err(message),
                Err(_) => return Ok(0),
            }
        }
    }

    /// Acks the in-flight chunk (if any) with `result` and clears the borrowed-chunk cursor.
    fn finish_current(&mut self, result: Result<(), String>) {
        if self.in_flight {
            let _ = self.ack.send(result);
            self.in_flight = false;
        }
        self.current_ptr = ptr::null();
        self.current_len = 0;
        self.current_offset = 0;
    }
}

/// Producer half of the chunk channel: hands a borrowed chunk to the consumer and blocks until it
/// is acked. Held by [`WriterHandle`](super::WriterHandle) (the host-facing write handle).
///
/// Must never be `Clone` (and holding a `Receiver` makes it `!Sync`): the ack protocol relies on
/// strict alternation — one chunk sent, one ack received — which a second producer would break.
pub(crate) struct ChunkProducer {
    data: SyncSender<ChunkResult>,
    /// Receiving half of the stream's single ack channel; closed (dropped) by consumer teardown,
    /// which is what releases a producer parked here mid-chunk.
    ack: Receiver<Result<(), String>>,
}

impl ChunkProducer {
    /// Sends `data` as a borrowed chunk and blocks until the consumer acks it, propagating the
    /// consumer's per-chunk result. Returns `Err` if the consumer is gone.
    pub(crate) fn send(&self, data: &[u8]) -> Result<(), String> {
        if data.is_empty() {
            return Ok(());
        }
        // Safety: the ack protocol guarantees `data` stays alive until the ack is received.
        let chunk = RawChunk {
            ptr: data.as_ptr(),
            len: data.len(),
        };
        self.data
            .send(Ok(chunk))
            .map_err(|_| "stream closed".to_string())?;
        self.ack.recv().map_err(|_| "stream closed".to_string())?
    }
}

/// The worker's input adapter: a [`Read`] over the chunks pushed by a
/// [`WriterHandle`](super::WriterHandle).
pub(crate) struct ChannelReader {
    consumer: ChunkConsumer,
}

impl ChannelReader {
    pub(crate) fn new(consumer: ChunkConsumer) -> Self {
        Self { consumer }
    }

    /// Acks the in-flight chunk with the worker's terminal error so a
    /// [`WriterHandle::write`](super::WriterHandle::write) blocked on that chunk fails with the
    /// real cause instead of a generic disconnect.
    pub(crate) fn fail(&mut self, message: String) {
        self.consumer.finish_current(Err(message));
    }
}

impl Read for ChannelReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.consumer.read(buffer).map_err(std::io::Error::other)
    }
}
