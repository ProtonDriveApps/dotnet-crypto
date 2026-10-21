use super::{EncryptedMessage, InteropError, UnsafePtr, WriterHandle, catch_error};

/// Parses an encrypted PGP message into a handle written to `out_message`.
///
/// Reads `message_len` bytes at `message`, decoding them as ASCII armor when `is_armored` is true
/// or as raw bytes otherwise, and writes a fresh handle into `*out_message` (release with
/// `pgp_message_destroy`). Returns a failure error if parsing fails.
///
/// # Safety
/// `message` must be valid for `message_len` bytes (or null when `message_len == 0`); `out_message`
/// must be a non-null, writable handle out-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_message_new(
    message: *const u8,
    message_len: usize,
    is_armored: bool,
    out_message: *mut *mut EncryptedMessage,
) -> InteropError {
    catch_error(|| {
        let data = UnsafePtr::get_slice(message, message_len)?;
        let message = if is_armored {
            EncryptedMessage::from_armor(data)
        } else {
            EncryptedMessage::from_bytes(data)
        }
        .map_err(|error| error.to_string())?;

        *UnsafePtr::ref_mut(out_message)? = UnsafePtr::new_raw(message);
        Ok(())
    })
}

/// Writes the number of key packets in an encrypted message into `*out_count`.
///
/// `ptr` is a message handle from `pgp_message_new`; the count of its leading key packets is
/// written into `*out_count`.
///
/// # Safety
/// `ptr` must be a live message handle from `pgp_message_new`; `out_count` must be a non-null,
/// writable `*mut usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_message_key_packet_split(
    ptr: *const EncryptedMessage,
    out_count: *mut usize,
) -> InteropError {
    catch_error(|| {
        *UnsafePtr::ref_mut(out_count)? = UnsafePtr::as_ref(ptr)?.as_key_packets_unchecked().len();
        Ok(())
    })
}

/// Releases an encrypted-message handle created by `pgp_message_new`.
///
/// # Safety
/// `ptr` must be a live message handle from `pgp_message_new` and must not be used after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_message_destroy(ptr: *mut EncryptedMessage) {
    UnsafePtr::drop_raw(ptr);
}

/// Pushes bytes into a streaming message writer handle.
///
/// Writes `buffer_len` bytes from `buffer` into the writer identified by `ptr` and writes the
/// number of bytes consumed into `*data_written`.
///
/// # Safety
/// `ptr` must be a live writer handle from a stream-open call; `buffer` must be valid for
/// `buffer_len` bytes (or null when `buffer_len == 0`); `data_written` must be a non-null, writable
/// `*mut usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_message_writer_write(
    ptr: *mut WriterHandle,
    buffer: *const u8,
    buffer_len: usize,
    data_written: *mut usize,
) -> InteropError {
    catch_error(|| {
        *UnsafePtr::ref_mut(data_written)? =
            UnsafePtr::ref_mut(ptr)?.write(UnsafePtr::get_slice(buffer, buffer_len)?)?;
        Ok(())
    })
}

/// Finalizes a streaming message writer handle, flushing any remaining output.
///
/// `ptr` is a writer handle from a stream-open call; after this returns successfully no further
/// writes should be performed.
///
/// # Safety
/// `ptr` must be a live writer handle from a stream-open call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_message_writer_close(ptr: *mut WriterHandle) -> InteropError {
    catch_error(|| UnsafePtr::ref_mut(ptr)?.close())
}

/// Releases a streaming message writer handle.
///
/// # Safety
/// `ptr` must be a live writer handle from a stream-open call and must not be used after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pgp_message_writer_destroy(ptr: *mut WriterHandle) {
    UnsafePtr::drop_raw(ptr);
}

#[cfg(test)]
mod tests;
