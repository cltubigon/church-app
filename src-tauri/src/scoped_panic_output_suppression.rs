//! Process-start panic-hook routing for one payload-free private boundary.

use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind, set_hook, take_hook},
    sync::{
        Once,
        atomic::{AtomicBool, Ordering},
    },
};

static INSTALL_ROUTER: Once = Once::new();
static ROUTER_INSTALLED: AtomicBool = AtomicBool::new(false);

std::thread_local! {
    static OUTPUT_SUPPRESSED_FOR_CURRENT_THREAD: Cell<bool> = const { Cell::new(false) };
}

/// Installs one permanent delegating hook before the application creates any
/// worker thread. This must remain the first operation in the Windows entry
/// path because stable Rust cannot atomically wrap an existing panic hook.
pub(crate) fn install_before_worker_threads() {
    INSTALL_ROUTER.call_once(|| {
        let previous_hook = take_hook();
        set_hook(Box::new(move |panic_info| {
            let suppressed = OUTPUT_SUPPRESSED_FOR_CURRENT_THREAD
                .try_with(Cell::get)
                .unwrap_or(false);
            if !suppressed {
                previous_hook(panic_info);
            }
        }));
        ROUTER_INSTALLED.store(true, Ordering::Release);
    });
}

struct SuppressionReset(bool);

impl Drop for SuppressionReset {
    fn drop(&mut self) {
        let _ = OUTPUT_SUPPRESSED_FOR_CURRENT_THREAD.try_with(|suppressed| suppressed.set(self.0));
    }
}

/// Runs one unwind boundary with panic-hook output disabled only for the
/// current thread. The panic payload is discarded without inspection.
pub(crate) fn catch_unwind_without_output<T>(operation: impl FnOnce() -> T) -> Result<T, ()> {
    if !ROUTER_INSTALLED.load(Ordering::Acquire) {
        #[cfg(not(test))]
        return Err(());
    }

    let previous = OUTPUT_SUPPRESSED_FOR_CURRENT_THREAD
        .try_with(|suppressed| suppressed.replace(true))
        .unwrap_or(false);
    let reset = SuppressionReset(previous);
    let outcome = catch_unwind(AssertUnwindSafe(operation)).map_err(|_| ());
    drop(reset);
    outcome
}
