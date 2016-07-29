#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

extern crate libc;
pub mod nspr;

use libc::c_char;
use nspr::PRFileDesc;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum SECStatus {
    SECWouldBlock = -2,
    SECFailure = -1,
    SECSuccess = 0,
}
pub use self::SECStatus::*;

extern "C" {
    pub fn NSS_NoDB_Init(_configdir: *const c_char) -> SECStatus;
    pub fn NSS_SetDomesticPolicy() -> SECStatus;
    pub fn SSL_ImportFD(model: *mut PRFileDesc, fd: *mut PRFileDesc) -> *mut PRFileDesc;
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    macro_rules! assert_ok {
        ($e:expr) => { assert_eq!(unsafe { $e }, SECSuccess) }
    }

    #[test]
    fn init() {
        assert_ok!(NSS_NoDB_Init(ptr::null()));
    }

    #[test]
    fn set_domestic() {
        init();
        assert_ok!(NSS_SetDomesticPolicy());
    }
}
