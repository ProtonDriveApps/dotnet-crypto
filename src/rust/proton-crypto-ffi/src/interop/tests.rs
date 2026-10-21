use super::memory::interop_memory_free;
use super::{catch_panic, malloc_bytes};
#[test]
fn catch_panic_passes_through_ok_and_err() {
    assert_eq!(catch_panic(|| Ok::<i32, String>(7)), Ok(7));
    assert_eq!(
        catch_panic(|| Err::<i32, String>("nope".to_string())),
        Err("nope".to_string())
    );
}

#[test]
fn catch_panic_converts_panic_to_err() {
    let result: Result<i32, String> = catch_panic(|| panic!("kaboom"));
    assert!(
        result.is_err_and(|message| message.contains("kaboom")),
        "panic should become an Err carrying its message"
    );
}

#[test]
fn ffi_interop_memory_free_null_is_noop() {
    unsafe { interop_memory_free(std::ptr::null_mut()) };
}

#[test]
fn ffi_interop_memory_free_frees_malloc_bytes() {
    let ptr = malloc_bytes(b"hello").expect("allocation should succeed");
    assert!(!ptr.is_null());
    unsafe { interop_memory_free(ptr.cast()) };
}

#[test]
fn malloc_bytes_empty_is_ok_null() {
    // Empty input is the only case that yields a null pointer (paired with a zero length).
    assert!(
        malloc_bytes(b"")
            .expect("empty input is not an error")
            .is_null()
    );
}
