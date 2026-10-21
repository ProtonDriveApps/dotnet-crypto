use std::slice;

/// Namespace for the helpers that convert host-supplied raw pointers to and from
/// Rust values at the FFI boundary.
pub(crate) struct UnsafePtr;
impl UnsafePtr {
    /// Boxes a value and returns the raw pointer handed to the host as a typed handle.
    pub fn new_raw<T>(value: T) -> *mut T {
        Box::into_raw(Box::new(value))
    }

    /// Borrows a host-supplied `*const` pointer (parameter struct or read-only handle),
    /// failing on null.
    ///
    /// # Safety
    /// When non-null, `ptr` must point to a live, valid `T` that outlives the returned
    /// reference.
    pub fn as_ref<'a, T>(ptr: *const T) -> Result<&'a T, String> {
        unsafe { ptr.as_ref() }.ok_or_else(|| "invalid pointer".to_string())
    }

    /// Mutably borrows a host-supplied `*mut` pointer (output location or mutable handle),
    /// failing on null.
    ///
    /// # Safety
    /// When non-null, `ptr` must point to a live, writable `T` with no other live
    /// references to it, outliving the returned reference.
    pub fn ref_mut<'a, T>(ptr: *mut T) -> Result<&'a mut T, String> {
        unsafe { ptr.as_mut() }.ok_or_else(|| "invalid pointer".to_string())
    }

    /// Releases a typed handle created by [`UnsafePtr::new_raw`]. Null is a no-op.
    ///
    /// # Safety
    /// `ptr` must be null or a live handle from [`UnsafePtr::new_raw`]; it must not be used
    /// afterwards.
    pub fn drop_raw<T>(ptr: *mut T) {
        if !ptr.is_null() {
            drop(unsafe { Box::from_raw(ptr) });
        }
    }

    /// Converts an optional FFI pointer pair (`has_x: bool`, `x: *const T`) into an
    /// optional reference; the pointer is ignored when `has` is false.
    ///
    /// # Safety
    /// When `has` is true, the pointer must satisfy [`UnsafePtr::as_ref`]'s contract.
    pub fn maybe_ref<'a, T>(ptr: *const T, has: bool) -> Result<Option<&'a T>, String> {
        has.then(|| Self::as_ref(ptr)).transpose()
    }

    /// Borrows a host-provided data array as a slice. `len == 0` yields an empty slice
    /// (the pointer may be null in that case).
    ///
    /// # Safety
    /// When `len > 0`, `ptr` must point to `len` consecutive initialized `T` values that
    /// outlive the returned slice.
    pub fn get_slice<'a, T>(ptr: *const T, len: usize) -> Result<&'a [T], String> {
        if len == 0 {
            Ok(&[])
        } else if ptr.is_null() {
            Err("invalid pointer".to_string())
        } else {
            Ok(unsafe { slice::from_raw_parts(ptr, len) })
        }
    }

    /// Borrows a mutable host-provided data array as a slice. `len == 0` yields an empty slice
    /// (the pointer may be null in that case).
    ///
    /// # Safety
    /// When `len > 0`, `ptr` must point to `len` consecutive initialized `T` values that
    /// outlive the returned slice.
    pub fn get_slice_mut<'a, T>(ptr: *mut T, len: usize) -> Result<&'a mut [T], String> {
        if len == 0 {
            Ok(&mut [])
        } else if ptr.is_null() {
            Err("invalid pointer".to_string())
        } else {
            Ok(unsafe { slice::from_raw_parts_mut(ptr, len) })
        }
    }

    /// Borrows a host-provided array of typed handles as a slice of references.
    ///
    /// `len == 0` yields an empty slice (the array pointer may be null in that case).
    ///
    /// # Safety
    /// When `len > 0`, `ptr` must point to `len` consecutive, non-null handles, each
    /// referencing a live `T` (as produced by [`UnsafePtr::new_raw`]) that outlives the
    /// returned slice.
    pub fn get_handle_slice<'a, T>(
        ptr: *const *const T,
        len: usize,
    ) -> Result<&'a [&'a T], String> {
        if len == 0 {
            Ok(&[])
        } else if ptr.is_null() {
            Err("invalid pointer".to_string())
        } else {
            let raw = unsafe { slice::from_raw_parts(ptr, len) };
            if raw.iter().any(|handle| handle.is_null()) {
                return Err("invalid pointer".to_string());
            }
            Ok(unsafe { slice::from_raw_parts(ptr.cast::<&T>(), len) })
        }
    }

    pub fn get_str<'a>(ptr: *const u8, len: usize) -> Result<&'a str, String> {
        std::str::from_utf8(UnsafePtr::get_slice(ptr, len)?).map_err(|error| error.to_string())
    }

    pub fn get_string(ptr: *const u8, len: usize) -> Result<String, String> {
        UnsafePtr::get_str(ptr, len).map(ToString::to_string)
    }
}
