#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate nss_sys;
pub mod nspr;

use nss_sys as ffi;
use std::ptr;
use std::result;

pub use nspr::Error;
pub type Result<T> = result::Result<T, Error>;

fn failed<T>() -> Result<T> { Err(Error::last()) }

fn status_to_result(status: ffi::SECStatus) -> Result<()> {
    // Must call this immediately after the NSS operation so that the
    // thread-local error state isn't stale.
    match status {
        ffi::SECSuccess => Ok(()),
        ffi::SECFailure => failed(),
        ffi::SECWouldBlock => Err(nspr::error::PR_WOULD_BLOCK_ERROR.into()),
    }
}

// TODO: What do I do about this init/shutdown stuff vs. lifetimes/safety?

pub fn init() -> Result<()> {
    nspr::init();
    status_to_result(unsafe {
        ffi::NSS_NoDB_Init(ptr::null())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn just_init() {
        init().unwrap();
    }
}
