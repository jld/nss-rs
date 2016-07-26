extern crate nss_sys;

use nss_sys::{NSS_NoDB_Init, SECSuccess};
use nss_sys::nspr::{PR_Init, PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL};
use std::ptr;
use std::sync::{Once, ONCE_INIT};

macro_rules! assert_success {
    ($e:expr) => { assert_eq!(unsafe { $e }, SECSuccess) }
}

// TODO: bind GetError and make these things return `Result`s.
// TODO: What do I do about this init/shutdown stuff vs. lifetimes/safety?

pub fn init() {
    init_nspr();
    assert_success!(NSS_NoDB_Init(ptr::null()));
}

fn init_nspr() {
    // NSPR initialization is done implicitly on the first call to any
    // API, but this "run once" check is thread-unsafe -- NSPR's
    // equivalent of `Once` can't be used because its threading layer
    // isn't initialized yet, and its atomics are polyfilled with
    // thread mutexes on some platforms so they're also off-limits.
    static PR_INIT_ONCE: Once = ONCE_INIT;
    PR_INIT_ONCE.call_once(|| {
        // These argument values haven't been used since before NSPR
        // was released as open source, but fill in something reasonable.
        unsafe { PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 0) };
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn just_init() {
        init();
    }
}
