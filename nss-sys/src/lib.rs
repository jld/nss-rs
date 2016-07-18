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
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn init() {
        let status = unsafe { NSS_NoDB_Init(ptr::null()) };
        assert_eq!(status, SECSuccess);
    }
}
