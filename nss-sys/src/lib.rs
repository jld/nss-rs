#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)] // for CK_STUFF; could lower if cryptoki becomes a submodule
#![allow(non_snake_case)]

extern crate libc;
pub mod nspr;
pub mod cert;

use libc::{c_char, c_uchar, c_uint, c_ulong, c_void};
use nspr::{PRFileDesc, PRBool, PRInt32, PRUint16};

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
pub type SSLVersionRange = SSLVersionRangeStr;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SSLProtocolVariant {
    ssl_variant_stream = 0,
    ssl_variant_datagram = 1,
}
pub use self::SSLProtocolVariant::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SSLVersionRangeStr {
    pub min: PRUint16,
    pub max: PRUint16,
}

pub const SSL_LIBRARY_VERSION_2: PRUint16 = 0x0002;
pub const SSL_LIBRARY_VERSION_3_0: PRUint16 = 0x0300;
pub const SSL_LIBRARY_VERSION_TLS_1_0: PRUint16 = 0x0301;
pub const SSL_LIBRARY_VERSION_TLS_1_1: PRUint16 = 0x0302;
pub const SSL_LIBRARY_VERSION_TLS_1_2: PRUint16 = 0x0303;
pub const SSL_LIBRARY_VERSION_TLS_1_3: PRUint16 = 0x0304;

// Ciphersuite code points.  Many of these are one or more of:
// deliberately insecure, insecure due to advances in cryptanalysis,
// obsolete for other reasons, and/or no longer implemented by NSS.
pub const TLS_NULL_WITH_NULL_NULL: PRUint16 = 0x0000;
pub const TLS_RSA_WITH_NULL_MD5: PRUint16 = 0x0001;
pub const TLS_RSA_WITH_NULL_SHA: PRUint16 = 0x0002;
pub const TLS_RSA_EXPORT_WITH_RC4_40_MD5: PRUint16 = 0x0003;
pub const TLS_RSA_WITH_RC4_128_MD5: PRUint16 = 0x0004;
pub const TLS_RSA_WITH_RC4_128_SHA: PRUint16 = 0x0005;
pub const TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5: PRUint16 = 0x0006;
pub const TLS_RSA_WITH_IDEA_CBC_SHA: PRUint16 = 0x0007;
pub const TLS_RSA_EXPORT_WITH_DES40_CBC_SHA: PRUint16 = 0x0008;
pub const TLS_RSA_WITH_DES_CBC_SHA: PRUint16 = 0x0009;
pub const TLS_RSA_WITH_3DES_EDE_CBC_SHA: PRUint16 = 0x000a;
pub const TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA: PRUint16 = 0x000b;
pub const TLS_DH_DSS_WITH_DES_CBC_SHA: PRUint16 = 0x000c;
pub const TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA: PRUint16 = 0x000d;
pub const TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA: PRUint16 = 0x000e;
pub const TLS_DH_RSA_WITH_DES_CBC_SHA: PRUint16 = 0x000f;
pub const TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA: PRUint16 = 0x0010;
pub const TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA: PRUint16 = 0x0011;
pub const TLS_DHE_DSS_WITH_DES_CBC_SHA: PRUint16 = 0x0012;
pub const TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA: PRUint16 = 0x0013;
pub const TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA: PRUint16 = 0x0014;
pub const TLS_DHE_RSA_WITH_DES_CBC_SHA: PRUint16 = 0x0015;
pub const TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA: PRUint16 = 0x0016;
pub const TLS_DH_anon_EXPORT_WITH_RC4_40_MD5: PRUint16 = 0x0017;
pub const TLS_DH_anon_WITH_RC4_128_MD5: PRUint16 = 0x0018;
pub const TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA: PRUint16 = 0x0019;
pub const TLS_DH_anon_WITH_DES_CBC_SHA: PRUint16 = 0x001a;
pub const TLS_DH_anon_WITH_3DES_EDE_CBC_SHA: PRUint16 = 0x001b;
pub const SSL_FORTEZZA_DMS_WITH_NULL_SHA: PRUint16 = 0x001c;
pub const SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA: PRUint16 = 0x001d;
pub const SSL_FORTEZZA_DMS_WITH_RC4_128_SHA: PRUint16 = 0x001e;
pub const TLS_RSA_WITH_AES_128_CBC_SHA: PRUint16 = 0x002F;
pub const TLS_DH_DSS_WITH_AES_128_CBC_SHA: PRUint16 = 0x0030;
pub const TLS_DH_RSA_WITH_AES_128_CBC_SHA: PRUint16 = 0x0031;
pub const TLS_DHE_DSS_WITH_AES_128_CBC_SHA: PRUint16 = 0x0032;
pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA: PRUint16 = 0x0033;
pub const TLS_DH_anon_WITH_AES_128_CBC_SHA: PRUint16 = 0x0034;
pub const TLS_RSA_WITH_AES_256_CBC_SHA: PRUint16 = 0x0035;
pub const TLS_DH_DSS_WITH_AES_256_CBC_SHA: PRUint16 = 0x0036;
pub const TLS_DH_RSA_WITH_AES_256_CBC_SHA: PRUint16 = 0x0037;
pub const TLS_DHE_DSS_WITH_AES_256_CBC_SHA: PRUint16 = 0x0038;
pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA: PRUint16 = 0x0039;
pub const TLS_DH_anon_WITH_AES_256_CBC_SHA: PRUint16 = 0x003A;
pub const TLS_RSA_WITH_NULL_SHA256: PRUint16 = 0x003B;
pub const TLS_RSA_WITH_AES_128_CBC_SHA256: PRUint16 = 0x003C;
pub const TLS_RSA_WITH_AES_256_CBC_SHA256: PRUint16 = 0x003D;
pub const TLS_DHE_DSS_WITH_AES_128_CBC_SHA256: PRUint16 = 0x0040;
pub const TLS_RSA_WITH_CAMELLIA_128_CBC_SHA: PRUint16 = 0x0041;
pub const TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA: PRUint16 = 0x0042;
pub const TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA: PRUint16 = 0x0043;
pub const TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA: PRUint16 = 0x0044;
pub const TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA: PRUint16 = 0x0045;
pub const TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA: PRUint16 = 0x0046;
pub const TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA: PRUint16 = 0x0062;
pub const TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA: PRUint16 = 0x0063;
pub const TLS_RSA_EXPORT1024_WITH_RC4_56_SHA: PRUint16 = 0x0064;
pub const TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA: PRUint16 = 0x0065;
pub const TLS_DHE_DSS_WITH_RC4_128_SHA: PRUint16 = 0x0066;
pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: PRUint16 = 0x0067;
pub const TLS_DHE_DSS_WITH_AES_256_CBC_SHA256: PRUint16 = 0x006A;
pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: PRUint16 = 0x006B;
pub const TLS_RSA_WITH_CAMELLIA_256_CBC_SHA: PRUint16 = 0x0084;
pub const TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA: PRUint16 = 0x0085;
pub const TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA: PRUint16 = 0x0086;
pub const TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA: PRUint16 = 0x0087;
pub const TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA: PRUint16 = 0x0088;
pub const TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA: PRUint16 = 0x0089;
pub const TLS_RSA_WITH_SEED_CBC_SHA: PRUint16 = 0x0096;
pub const TLS_RSA_WITH_AES_128_GCM_SHA256: PRUint16 = 0x009C;
pub const TLS_RSA_WITH_AES_256_GCM_SHA384: PRUint16 = 0x009D;
pub const TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: PRUint16 = 0x009E;
pub const TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: PRUint16 = 0x009F;
pub const TLS_DHE_DSS_WITH_AES_128_GCM_SHA256: PRUint16 = 0x00A2;
pub const TLS_DHE_DSS_WITH_AES_256_GCM_SHA384: PRUint16 = 0x00A3;
pub const TLS_ECDH_ECDSA_WITH_NULL_SHA: PRUint16 = 0xC001;
pub const TLS_ECDH_ECDSA_WITH_RC4_128_SHA: PRUint16 = 0xC002;
pub const TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA: PRUint16 = 0xC003;
pub const TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA: PRUint16 = 0xC004;
pub const TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA: PRUint16 = 0xC005;
pub const TLS_ECDHE_ECDSA_WITH_NULL_SHA: PRUint16 = 0xC006;
pub const TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: PRUint16 = 0xC007;
pub const TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: PRUint16 = 0xC008;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: PRUint16 = 0xC009;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: PRUint16 = 0xC00A;
pub const TLS_ECDH_RSA_WITH_NULL_SHA: PRUint16 = 0xC00B;
pub const TLS_ECDH_RSA_WITH_RC4_128_SHA: PRUint16 = 0xC00C;
pub const TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA: PRUint16 = 0xC00D;
pub const TLS_ECDH_RSA_WITH_AES_128_CBC_SHA: PRUint16 = 0xC00E;
pub const TLS_ECDH_RSA_WITH_AES_256_CBC_SHA: PRUint16 = 0xC00F;
pub const TLS_ECDHE_RSA_WITH_NULL_SHA: PRUint16 = 0xC010;
pub const TLS_ECDHE_RSA_WITH_RC4_128_SHA: PRUint16 = 0xC011;
pub const TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: PRUint16 = 0xC012;
pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: PRUint16 = 0xC013;
pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: PRUint16 = 0xC014;
pub const TLS_ECDH_anon_WITH_NULL_SHA: PRUint16 = 0xC015;
pub const TLS_ECDH_anon_WITH_RC4_128_SHA: PRUint16 = 0xC016;
pub const TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA: PRUint16 = 0xC017;
pub const TLS_ECDH_anon_WITH_AES_128_CBC_SHA: PRUint16 = 0xC018;
pub const TLS_ECDH_anon_WITH_AES_256_CBC_SHA: PRUint16 = 0xC019;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: PRUint16 = 0xC023;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: PRUint16 = 0xC024;
pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: PRUint16 = 0xC027;
pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: PRUint16 = 0xC028;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: PRUint16 = 0xC02B;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: PRUint16 = 0xC02C;
pub const TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256: PRUint16 = 0xC02D;
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: PRUint16 = 0xC02F;
pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: PRUint16 = 0xC030;
pub const TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256: PRUint16 = 0xC031;
pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: PRUint16 = 0xCCA8;
pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: PRUint16 = 0xCCA9;
pub const TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: PRUint16 = 0xCCAA;
pub const SSL_RSA_FIPS_WITH_DES_CBC_SHA: PRUint16 = 0xfefe;
pub const SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA: PRUint16 = 0xfeff;
pub const SSL_EN_RC4_128_WITH_MD5: PRUint16 = 0xFF01;
pub const SSL_EN_RC4_128_EXPORT40_WITH_MD5: PRUint16 = 0xFF02;
pub const SSL_EN_RC2_128_CBC_WITH_MD5: PRUint16 = 0xFF03;
pub const SSL_EN_RC2_128_CBC_EXPORT40_WITH_MD5: PRUint16 = 0xFF04;
pub const SSL_EN_IDEA_128_CBC_WITH_MD5: PRUint16 = 0xFF05;
pub const SSL_EN_DES_64_CBC_WITH_MD5: PRUint16 = 0xFF06;
pub const SSL_EN_DES_192_EDE3_CBC_WITH_MD5: PRUint16 = 0xFF07;
pub const SSL_RSA_OLDFIPS_WITH_3DES_EDE_CBC_SHA: PRUint16 = 0xffe0;
pub const SSL_RSA_OLDFIPS_WITH_DES_CBC_SHA: PRUint16 = 0xffe1;

// Experimental TLS 1.3 AEAD suites
pub const TLS_AES_128_GCM_SHA256: PRUint16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: PRUint16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: PRUint16 = 0x1303;

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
    pub fn SSL_VersionRangeSet(fd: *mut PRFileDesc, vrange: *const SSLVersionRange) -> SECStatus;
    pub fn SSL_VersionRangeGet(fd: *mut PRFileDesc, vrange: *mut SSLVersionRange) -> SECStatus;
    pub fn SSL_VersionRangeSetDefault(protocolVariant: SSLProtocolVariant,
                                      vrange: *const SSLVersionRange) -> SECStatus;
    pub fn SSL_VersionRangeGetDefault(protocolVariant: SSLProtocolVariant,
                                      vrange: *mut SSLVersionRange) -> SECStatus;
    pub fn SSL_VersionRangeGetSupported(protocolVariant: SSLProtocolVariant,
                                        vrange: *mut SSLVersionRange) -> SECStatus;
    pub fn SSL_GetImplementedCiphers() -> *const PRUint16;
    pub fn SSL_GetNumImplementedCiphers() -> PRUint16;
    pub fn SSL_CipherPrefSet(fd: *mut PRFileDesc, cipher: PRInt32, enabled: PRBool) -> SECStatus;
    pub fn SSL_CipherPrefGet(fd: *mut PRFileDesc, cipher: PRInt32, enabled: *mut PRBool)
                             -> SECStatus;
    pub fn SSL_CipherPrefSetDefault(cipher: PRInt32, enabled: PRBool) -> SECStatus;
    pub fn SSL_CipherPrefGetDefault(cipher: PRInt32, enabled: *mut PRBool) -> SECStatus;
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
