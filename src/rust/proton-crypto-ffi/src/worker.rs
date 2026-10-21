//! Threading and dispatch: how a work unit reaches a thread — the host's ([`HostWorkDispatcherFn`])
//! or a crate-spawned fallback — and the lifecycle of the worker running it.

use std::ffi::c_void;
use std::mem::ManuallyDrop;
use std::sync::mpsc::Receiver;

/// One-shot work unit: `fun(args)` is invoked by the host or fallback thread.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Task {
    pub fun: unsafe extern "C" fn(*mut c_void),
    pub args: *mut c_void,
}

/// Host callback passed to streaming FFI entry points. Return 1 when the host took ownership of
/// running `task` (Rust will not spawn a fallback thread). Return 0 to fall back to spawning a
/// dedicated thread for this task. Pass `None` to always use fallback threads.
///
/// The return value crosses the boundary as a Rust `bool`, so the host must return exactly 0
/// or 1. A host that takes ownership MUST run the task asynchronously — never inline on the
/// calling thread: stream workers park waiting for reads/writes on the handle the current call
/// has not yet returned, so running the task synchronously deadlocks. It MUST also eventually
/// run the task exactly once; a task that never runs leaves the handle's destroy call blocked
/// waiting for the worker's completion. Tasks are long-lived (they run for the lifetime of the
/// stream), so hosts scheduling onto a bounded pool should account for that.
pub type HostWorkDispatcherFn = unsafe extern "C" fn(task: Task) -> bool;

/// Runs `task` on the host dispatcher when provided (and accepted), otherwise on a detached
/// fallback thread. Worker completion is observed through the completion channel, never by
/// joining a thread — both dispatch paths behave identically.
pub fn dispatch_task(task: Task, work_dispatcher: Option<HostWorkDispatcherFn>) {
    if let Some(dispatch) = work_dispatcher
        && unsafe { dispatch(task) }
    {
        return;
    }

    // Convert the `c_void` to a usize to pass it across thread boundary.
    let args = task.args as usize;
    let fun = task.fun;
    std::thread::spawn(move || unsafe {
        fun(args as *mut c_void);
    });
}

/// A dispatch-ready worker whose launch is deferred: the entry fn pointer plus its already-erased
/// boxed context — exactly what [`dispatch_task`] will receive. The type erasure to `*mut c_void`
/// is the same one the FFI dispatch boundary performs anyway, just done at construction instead of
/// through a boxed closure.
struct PendingTask {
    task: Task,
    dispatcher: Option<HostWorkDispatcherFn>,
    /// Reclaims and drops the boxed context if the task never runs.
    drop_ctx: unsafe fn(*mut c_void),
}

// Safety: `task.args` is the unique owner of a `Box<C>` where `C: Send` — enforced by
// [`WorkerLifecycle::pending`]'s bound — and no alias exists until the entry fn reclaims it.
unsafe impl Send for PendingTask {}

impl PendingTask {
    /// Dispatches the task, passing context ownership to the entry fn (so the destructor is
    /// disarmed).
    fn run(self) {
        let this = ManuallyDrop::new(self);
        dispatch_task(this.task, this.dispatcher);
    }
}

impl Drop for PendingTask {
    fn drop(&mut self) {
        // Never dispatched: reclaim the boxed context — and with it the captured job and its owned
        // inputs — without running it.
        unsafe { (self.drop_ctx)(self.task.args) };
    }
}

/// Monomorphized context destructor stored in [`PendingTask::drop_ctx`].
///
/// # Safety
/// `ctx` must be a `Box<C>` turned raw by [`WorkerLifecycle::pending`] and not yet reclaimed.
unsafe fn drop_context<C>(ctx: *mut c_void) {
    drop(unsafe { Box::from_raw(ctx.cast::<C>()) });
}

/// The deferred dispatch + completion result of a worker, plus the idempotency guard shared by
/// the stream handles' teardown.
///
/// The completion channel is the only lifecycle mechanism: [`WorkerLifecycle::finish`] waits for
/// the worker's completion message, not for thread exit (host-dispatched workers have no join
/// handle, and fallback threads are spawned detached). Worker entries must therefore drop
/// everything that touches handle- or host-owned resources — the job with its captured callbacks
/// and any shared state — *before* sending the completion; after `finish` returns, the worker only
/// unwinds its own stack.
///
/// A handle whose worker parks on a channel MUST drop its channel half *before* calling
/// [`WorkerLifecycle::finish`]: waiting first would hang (see the stream chunk protocol).
pub(crate) struct WorkerLifecycle<T: Send> {
    /// `Some` until the worker is dispatched. Eager handles call `ensure_started` right after
    /// construction; lazy handles hold it until their first use. Dropping it un-dispatched drops
    /// the boxed context (and its owned inputs) without running it.
    start: Option<PendingTask>,
    /// Receiving half of the worker's oneshot completion channel; the sending half lives in the
    /// worker context and delivers the job result at the end of the worker entry.
    completion: Receiver<Result<T, String>>,
    /// Noun used in the "<thread> thread exited without a result" error, e.g. "reader" / "writer".
    thread: &'static str,
    finished: bool,
}

impl<T: Send> WorkerLifecycle<T> {
    /// A worker whose dispatch is deferred until the first [`WorkerLifecycle::ensure_started`]:
    /// `entry` will be handed `ctx` (boxed, erased) on the host dispatcher or a fallback thread.
    /// Eager callers construct this and call `ensure_started` immediately.
    pub fn pending<C: Send + 'static>(
        entry: unsafe extern "C" fn(*mut c_void),
        ctx: Box<C>,
        dispatcher: Option<HostWorkDispatcherFn>,
        completion: Receiver<Result<T, String>>,
        thread: &'static str,
    ) -> Self {
        Self {
            start: Some(PendingTask {
                task: Task {
                    fun: entry,
                    args: Box::into_raw(ctx).cast(),
                },
                dispatcher,
                drop_ctx: drop_context::<C>,
            }),
            completion,
            thread,
            finished: false,
        }
    }

    /// Dispatches the worker on first call; a no-op once started (and for eager handles).
    pub fn ensure_started(&mut self) {
        if let Some(start) = self.start.take() {
            start.run();
        }
    }

    /// Waits for the worker's completion result, or returns `None` if already finished or never
    /// started.
    ///
    /// The completion channel delivers exactly one result, so this must run at most once: the
    /// `finished` guard turns a second call (e.g. an explicit close() followed by Drop) into a
    /// no-op instead of a spurious "exited without a result" error.
    pub fn finish(&mut self) -> Option<Result<T, String>> {
        if self.finished {
            return None;
        }
        self.finished = true;

        // Never dispatched (a lazy handle dropped before its first use): drop the pending task —
        // and with it the boxed job and its owned inputs — and skip the join/wait. No worker ran,
        // so the completion would never be sent and `recv` would block forever.
        if self.start.take().is_some() {
            return None;
        }

        // No join: a panic in the job is caught and reported through the completion, and a panic
        // escaping the `extern "C"` entry aborts the process, so a join could never observe more
        // than the recv below does.
        Some(
            self.completion
                .recv()
                .unwrap_or_else(|_| Err(format!("{} thread exited without a result", self.thread))),
        )
    }
}
