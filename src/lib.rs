extern crate nss_sys;

use nss_sys::SECSuccess;
use std::ptr;

macro_rules! assert_success {
    ($e:expr) => { assert_eq!(unsafe { $e }, SECSuccess) }
}

// TODO: bind GetError and make these things return `Result`s.

// TODO: WTF do I do about this init/shutdown stuff vs. lifetimes/safety?

pub fn init() {
    assert_success!(nss_sys::NSS_NoDB_Init(ptr::null()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn just_init() {
        init();
    }
}
