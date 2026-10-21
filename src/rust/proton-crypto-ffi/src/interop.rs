//! Helper functions for compatibility with crossing the C boundary: error type, panic
//! containment, host-memory transfer ([`memory`]), pointer marshalling ([`ptr`]), and the
//! host IO callback adapters ([`io`]).

pub(crate) mod io;
pub(crate) mod memory;
pub(crate) mod ptr;

pub(crate) use io::{ForeignReader, ForeignWriter};
pub(crate) use memory::{copy_to_host_buffer, malloc_bytes, malloc_c_string};
pub(crate) use ptr::UnsafePtr;

use std::panic::{AssertUnwindSafe, catch_unwind};

pub trait FromId {
    type Output;

    fn from_id(value: u8) -> Self::Output;
}

pub trait ToId {
    type Input;

    fn to_id(value: Self::Input) -> Result<u8, String>;
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InteropError {
    pub message: *const u8,
    pub message_length: i32,
}

impl InteropError {
    pub const fn success() -> Self {
        Self {
            message: std::ptr::null_mut(),
            message_length: 0,
        }
    }

    pub fn failure(message: impl Into<String>) -> Self {
        let message = message.into();
        let bytes = message.as_bytes();
        let ptr = malloc_c_string(bytes);
        // A failed allocation yields a null pointer; pair it with length 0 so the host never sees a
        // null message paired with a non-zero length.
        let message_length = if ptr.is_null() { 0 } else { bytes.len() as i32 };
        Self {
            message: ptr.cast(),
            message_length,
        }
    }
}

/// Turns a caught panic payload into the panic message. Private: the one unavoidable `dyn`
/// (`catch_unwind`'s payload type) stays contained here.
fn map_panic<T>(result: Result<T, Box<dyn std::any::Any + Send>>) -> Result<T, String> {
    result.map_err(|panic| {
        if let Some(message) = panic.downcast_ref::<String>() {
            message.clone()
        } else if let Some(message) = panic.downcast_ref::<&str>() {
            (*message).to_string()
        } else {
            "native panic".to_string()
        }
    })
}

/// Convert the status of the operation to an `InteropError`.
///
/// Catches panics and converts them into `InteropError::failure`
/// Maps a success to an `InteropError::success`
/// Maps a failure to an `InteropError::failure`
pub fn catch_error<F>(operation: F) -> InteropError
where
    F: FnOnce() -> Result<(), String>,
{
    match map_panic(catch_unwind(AssertUnwindSafe(operation))) {
        Ok(Ok(())) => InteropError::success(),
        Ok(Err(message)) | Err(message) => InteropError::failure(message),
    }
}

/// Runs a fallible worker `operation`, converting any panic into `Err(String)`.
///
/// Companion to [`catch_error`] for the streaming worker entries, which are `extern "C"` and yield
/// their result through a channel/completion rather than an `InteropError`. Catching the panic here
/// keeps it from unwinding across the `extern "C"` boundary — which would abort the whole host
/// process — and lets the worker report it as an ordinary error, mirroring the non-streaming paths.
pub fn catch_panic<T, F>(operation: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String>,
{
    map_panic(catch_unwind(AssertUnwindSafe(operation))).unwrap_or_else(Err)
}

#[cfg(test)]
mod tests;
