#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate nss_sys;
pub mod nspr;

use nss_sys as ffi;
use std::mem;
use std::ptr;
use std::ops::Deref;

pub use nspr::error::{Error, Result, failed, PR_WOULD_BLOCK_ERROR};
pub use nspr::fd::{File,FileMethods,FileWrapper};

fn result_secstatus(status: ffi::SECStatus) -> Result<()> {
    // Must call this immediately after the NSS operation so that the
    // thread-local error state isn't stale.
    match status {
        ffi::SECSuccess => Ok(()),
        ffi::SECFailure => failed(),
        ffi::SECWouldBlock => Err(PR_WOULD_BLOCK_ERROR.into()),
    }
}

// TODO: What do I do about this init/shutdown stuff vs. lifetimes/safety?

pub fn init() -> Result<()> {
    nspr::init();
    result_secstatus(unsafe { ffi::NSS_NoDB_Init(ptr::null()) })
}

pub struct TLSSocket(File);
impl Deref for TLSSocket {
    type Target = File;
    fn deref(&self) -> &File { &self.0 }
}
impl TLSSocket {
    pub fn new(inner: File) -> Result<Self> {
        Self::new_with_model(inner, None)
    }
    pub fn new_with_model(inner: File, model: Option<Self>) -> Result<Self> {
        let raw_model = model.map_or(nspr::fd::null(), |fd| fd.as_raw_prfd());
        unsafe {
            let raw = ffi::SSL_ImportFD(raw_model, inner.as_raw_prfd());
            let sock = try!(File::from_raw_prfd_err(raw));
            mem::forget(inner);
            Ok(TLSSocket(sock))
        }
    }
    pub fn into_inner(self) -> File { self.0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn just_init() {
        init().unwrap();
    }
}
