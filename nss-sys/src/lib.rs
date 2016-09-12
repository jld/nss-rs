#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)] // for CK_STUFF; could lower if cryptoki becomes a submodule
#![allow(non_snake_case)]

extern crate libc;
pub mod nspr;
pub mod cert;

use libc::{c_char, c_uchar, c_uint, c_ulong, c_void};
use nspr::{PRFileDesc, PRBool};

pub use cert::{CERTCertificate, CERT_DestroyCertificate};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum SECStatus {
    SECWouldBlock = -2,
    SECFailure = -1,
    SECSuccess = 0,
}
pub use self::SECStatus::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum SECItemType {
    siBuffer = 0,
    siClearDataBuffer = 1,
    siCipherDataBuffer = 2,
    siDERCertBuffer = 3,
    siEncodedCertBuffer = 4,
    siDERNameBuffer = 5,
    siEncodedNameBuffer = 6,
    siAsciiNameString = 7,
    siAsciiString = 8,
    siDEROID = 9,
    siUnsignedInteger = 10,
    siUTCTime = 11,
    siGeneralizedTime = 12,
    siVisibleString = 13,
    siUTF8String = 14,
    siBMPString = 15,
}

pub type SECItem = SECItemStr;
pub type SECAlgorithmID = SECAlgorithmIDStr;
pub type PK11SlotInfo = PK11SlotInfoStr;

pub type CK_OBJECT_HANDLE = CK_ULONG;
pub type CK_ULONG = c_ulong;

pub enum NSSTrustDomainStr { }
pub enum NSSCertificateStr { }
pub enum PK11SlotInfoStr { }

#[derive(Debug)]
#[repr(C)]
pub struct SECItemStr {
    pub type_: SECItemType,
    pub data: *mut c_uchar,
    pub len: c_uint,
}

#[derive(Debug)]
#[repr(C)]
pub struct SECAlgorithmIDStr {
    pub algorithm: SECItem,
    pub parameters: SECItem,
}

pub type SSLBadCertHandler =
    Option<unsafe extern "C" fn (arg: *mut c_void, fd: *mut PRFileDesc) -> SECStatus>;

pub type SSLAuthCertificate =
    Option<unsafe extern "C" fn(arg: *mut c_void, fd: *mut PRFileDesc,
                                checkSig: PRBool, isServer: PRBool) -> SECStatus>;

extern "C" {
    pub fn NSS_NoDB_Init(_configdir: *const c_char) -> SECStatus;
    pub fn NSS_SetDomesticPolicy() -> SECStatus;
    pub fn SSL_ImportFD(model: *mut PRFileDesc, fd: *mut PRFileDesc) -> *mut PRFileDesc;
    pub fn SSL_PeerCertificate(fd: *mut PRFileDesc) -> *mut CERTCertificate;
    pub fn SSL_AuthCertificateHook(fd: *mut PRFileDesc, f: SSLAuthCertificate, arg: *mut c_void)
                                   -> SECStatus;
    pub fn SSL_BadCertHook(fd: *mut PRFileDesc, f: SSLBadCertHandler, arg: *mut c_void)
                           -> SECStatus;
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
