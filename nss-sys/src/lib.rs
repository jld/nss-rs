#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)] // for CK_STUFF; could lower if cryptoki becomes a submodule
#![allow(non_snake_case)]

extern crate libc;
pub mod nspr;
pub mod cert;

use libc::{c_char, c_uchar, c_uint, c_ulong, c_void};
use nspr::{PRFileDesc, PRBool, PRInt32};

pub use cert::{CERTCertificate, CERTCertList, CERTCertListNode,
               CERT_DestroyCertificate, CERT_DestroyCertList,
               CERT_VerifyCertName};

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

// Options:
pub const SSL_SECURITY: PRInt32 = 1;
pub const SSL_SOCKS: PRInt32 = 2;
pub const SSL_REQUEST_CERTIFICATE: PRInt32 = 3;
pub const SSL_HANDSHAKE_AS_CLIENT: PRInt32 = 5;
pub const SSL_HANDSHAKE_AS_SERVER: PRInt32 = 6;
pub const SSL_ENABLE_SSL2: PRInt32 = 7;
pub const SSL_ENABLE_SSL3: PRInt32 = 8;
pub const SSL_NO_CACHE: PRInt32 = 9;
pub const SSL_REQUIRE_CERTIFICATE: PRInt32 = 10;
pub const SSL_ENABLE_FDX: PRInt32 = 11;
pub const SSL_V2_COMPATIBLE_HELLO: PRInt32 = 12;
pub const SSL_ENABLE_TLS: PRInt32 = 13;
pub const SSL_ROLLBACK_DETECTION: PRInt32 = 14;
pub const SSL_NO_STEP_DOWN: PRInt32 = 15;
pub const SSL_BYPASS_PKCS11: PRInt32 = 16;
pub const SSL_NO_LOCKS: PRInt32 = 17;
pub const SSL_ENABLE_SESSION_TICKETS: PRInt32 = 18;
pub const SSL_ENABLE_DEFLATE: PRInt32 = 19;
pub const SSL_ENABLE_RENEGOTIATION: PRInt32 = 20;
pub const SSL_REQUIRE_SAFE_NEGOTIATION: PRInt32 = 21;
pub const SSL_ENABLE_FALSE_START: PRInt32 = 22;
pub const SSL_CBC_RANDOM_IV: PRInt32 = 23;
pub const SSL_ENABLE_OCSP_STAPLING: PRInt32 = 24;
pub const SSL_ENABLE_NPN: PRInt32 = 25;
pub const SSL_ENABLE_ALPN: PRInt32 = 26;
pub const SSL_REUSE_SERVER_ECDHE_KEY: PRInt32 = 27;
pub const SSL_ENABLE_FALLBACK_SCSV: PRInt32 = 28;
pub const SSL_ENABLE_SERVER_DHE: PRInt32 = 29;
pub const SSL_ENABLE_EXTENDED_MASTER_SECRET: PRInt32 = 30;
pub const SSL_ENABLE_SIGNED_CERT_TIMESTAMPS: PRInt32 = 31;
pub const SSL_REQUIRE_DH_NAMED_GROUPS: PRInt32 = 32;
pub const SSL_ENABLE_0RTT_DATA: PRInt32 = 33;

extern "C" {
    pub fn NSS_NoDB_Init(_configdir: *const c_char) -> SECStatus;
    pub fn NSS_SetDomesticPolicy() -> SECStatus;
    pub fn SSL_ImportFD(model: *mut PRFileDesc, fd: *mut PRFileDesc) -> *mut PRFileDesc;
    pub fn SSL_PeerCertificate(fd: *mut PRFileDesc) -> *mut CERTCertificate;
    pub fn SSL_PeerCertificateChain(fd: *mut PRFileDesc) -> *mut CERTCertList;
    pub fn SSL_AuthCertificateHook(fd: *mut PRFileDesc, f: SSLAuthCertificate, arg: *mut c_void)
                                   -> SECStatus;
    pub fn SSL_BadCertHook(fd: *mut PRFileDesc, f: SSLBadCertHandler, arg: *mut c_void)
                           -> SECStatus;
    pub fn SSL_SetURL(fd: *mut PRFileDesc, url: *const c_char) -> SECStatus;
    pub fn SSL_OptionSet(fd: *mut PRFileDesc, option: PRInt32, on: PRBool) -> SECStatus;
    pub fn SSL_OptionGet(fd: *mut PRFileDesc, option: PRInt32, on: *mut PRBool) -> SECStatus;
    pub fn SSL_OptionSetDefault(option: PRInt32, on: PRBool) -> SECStatus;
    pub fn SSL_OptionGetDefault(option: PRInt32, on: *mut PRBool) -> SECStatus;
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
