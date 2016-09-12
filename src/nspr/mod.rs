pub mod error;
pub mod fd;
pub mod net;
pub mod time;

use nss_sys::nspr as ffi;
use nspr::error::{Result, failed};

use std::sync::{Once, ONCE_INIT};

pub use self::error::Error;
pub use self::fd::File;

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
            ffi::PR_Init(ffi::PR_SYSTEM_THREAD, ffi::PR_PRIORITY_NORMAL, 0);
        }
    });
}

fn result_len32(rv: i32) -> Result<usize> {
    if rv >= 0 {
        Ok(rv as usize)
    } else {
        failed()
    }
}

fn result_prstatus(rv: ffi::PRStatus) -> Result<()> {
    match rv {
        ffi::PR_SUCCESS => Ok(()),
        ffi::PR_FAILURE => failed(),
    }
}

pub fn bool_from_nspr(b: ffi::PRBool) -> bool {
    match b {
        ffi::PR_FALSE => false,
        ffi::PR_TRUE => true,
        _ => unreachable!(),
    }
}

pub fn bool_to_nspr(b: bool) -> ffi::PRBool {
    if b {
        ffi::PR_TRUE
    } else {
        ffi::PR_FALSE
    }
}
