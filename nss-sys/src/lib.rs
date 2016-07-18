#![allow(non_upper_case_globals)]

extern crate libc;
#[macro_use]
mod util;

use libc::{c_char, c_int};

c_enum! {
    pub enum SECStatus: c_int {
        SECWouldBlock = -2,
        SECFailure = -1,
        SECSuccess = 0,
    }
}

extern "C" {
    pub fn NSS_NoDB_Init(_configdir: *const c_char) -> SECStatus;
    pub fn NSS_SetDomesticPolicy() -> SECStatus;
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
