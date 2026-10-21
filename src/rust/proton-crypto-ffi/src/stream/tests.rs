// A panic inside a streaming worker job must be caught inside the `extern "C"` worker entry and
// surfaced as an error through the handle. Without the catch, the panic unwinds across the FFI
// boundary and aborts the whole process — so if this regresses, the test binary aborts rather than
// failing cleanly.
#[test]
fn write_worker_catches_job_panic_instead_of_aborting() {
    let mut handle = super::spawn_write_worker(None, |_reader| panic!("boom-writer"));
    let message = handle
        .close()
        .expect_err("panicking write-worker job must surface as an error");
    assert!(
        message.contains("boom-writer"),
        "error should carry the panic message, got: {message}"
    );
}
