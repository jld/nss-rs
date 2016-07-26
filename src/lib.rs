extern crate libc;
extern crate nss_sys;
pub mod nspr;

use nss_sys as sys;
use std::ptr;
use std::result;

pub type Error = nspr::Error;
pub type Result<T> = result::Result<T, Error>;

fn status_to_result(status: sys::SECStatus) -> Result<()> {
    // Must call this immediately after the NSS operation so that the
    // thread-local error state isn't stale.
    match status {
        sys::SECSuccess => Ok(()),
        sys::SECFailure => Err(Error::last()),
        sys::SECWouldBlock => Err(nspr::error::PR_WOULD_BLOCK_ERROR.into()),
    }
}

macro_rules! nss_try {
    ($e:expr) => {
        // Automatically adding `unsafe` is a little scary, but the
        // idea is that `$e` will always(?) be an FFI call.
        try!(status_to_result(unsafe { $e }))
    }
}

// TODO: What do I do about this init/shutdown stuff vs. lifetimes/safety?

pub fn init() -> Result<()> {
    nspr::init();
    nss_try!(sys::NSS_NoDB_Init(ptr::null()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn just_init() {
        init().unwrap();
    }
}
