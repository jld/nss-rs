pub mod error;

use nss_sys::nspr as sys;
use std::sync::{Once, ONCE_INIT};

pub use self::error::Error;

pub fn init() {
    // NSPR initialization is done implicitly on the first call to any
    // API, but this "run once" check is thread-unsafe -- NSPR's
    // equivalent of `Once` can't be used because its threading layer
    // isn't initialized yet, and its atomics are polyfilled with
    // thread mutexes on some platforms so they're also off-limits.
    static PR_INIT_ONCE: Once = ONCE_INIT;
    PR_INIT_ONCE.call_once(|| {
        // These argument values haven't been used since before NSPR
        // was released as open source, but fill in something reasonable.
        unsafe {
            sys::PR_Init(sys::PR_SYSTEM_THREAD, sys::PR_PRIORITY_NORMAL, 0);
        }
    });
}
