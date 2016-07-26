extern crate nss_sys;
pub mod nspr;

use nss_sys as sys;
use std::ptr;

macro_rules! assert_success {
    ($e:expr) => { assert_eq!(unsafe { $e }, sys::SECSuccess) }
}

// TODO: bind GetError and make these things return `Result`s.
// TODO: What do I do about this init/shutdown stuff vs. lifetimes/safety?

pub fn init() {
    nspr::init();
    assert_success!(sys::NSS_NoDB_Init(ptr::null()));
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn just_init() {
        init();
    }
}
