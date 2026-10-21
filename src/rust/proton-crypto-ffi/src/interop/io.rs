//! [`Read`]/[`Write`] adapters over the host's IO callback vtables.

use std::io::{self, Read, Write};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ForeignWriter {
    pub sink: usize,
    // Attempt to write `buf_len` bytes from `buf` into `sink`, returning the number of bytes
    // written or a negative value on failure: write(sink, buf, buf_len)
    pub write: Option<unsafe extern "C" fn(usize, *const u8, usize) -> i64>,
}

impl ForeignWriter {
    pub fn is_null(self) -> bool {
        self.sink == 0 || self.write.is_none()
    }
}

impl Write for ForeignWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let Some(write_fn) = self.write else {
            return Err(io::Error::other("missing output writer"));
        };

        let count = unsafe { write_fn(self.sink, buf.as_ptr(), buf.len()) };
        if count < 0 {
            return Err(io::Error::other("output writer failed"));
        }
        // Never report more than the caller supplied: an over-reporting host would make safe
        // downstream code (`write_all` slicing off the written prefix) index out of bounds.
        match usize::try_from(count) {
            Ok(count) if count <= buf.len() => Ok(count),
            _ => Err(io::Error::other(
                "output writer reported more bytes than provided",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ForeignReader {
    pub ptr: usize,
    // Attempt to read up to `buf_len` bytes into `buf`, returning the number of bytes read and
    // setting the error code to -1 on failure or 1 at end of stream: read(ptr, buf, buf_len, code)
    pub read: Option<unsafe extern "C" fn(usize, *mut u8, usize, *mut i32) -> i64>,
}

impl Read for ForeignReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let Some(read_fn) = self.read else {
            return Err(io::Error::other("missing input reader"));
        };

        let mut error_code = 0i32;
        let count = unsafe { read_fn(self.ptr, buf.as_mut_ptr(), buf.len(), &raw mut error_code) };
        if error_code == -1 || count < 0 {
            return Err(io::Error::other("input reader failed"));
        }
        // Never report more than the buffer holds: an over-reporting host would make safe
        // downstream code (`BufReader`, `io::copy`) index out of bounds.
        //
        // Error code 1 flags end of stream; any bytes returned alongside it are still delivered
        // (the host reports end of stream again on the next call), and with no bytes the zero
        // count itself signals end of stream.
        match usize::try_from(count) {
            Ok(count) if count <= buf.len() => Ok(count),
            _ => Err(io::Error::other(
                "input reader reported more bytes than the buffer holds",
            )),
        }
    }
}
