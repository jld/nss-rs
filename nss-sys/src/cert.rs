/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use libc::{c_char, c_uint, c_int, c_void};
use nspr::{PLArenaPool, PRBool, PRUint32, PRCList};
use super::{SECItem, SECAlgorithmID, NSSTrustDomainStr, NSSCertificateStr, PK11SlotInfo, CK_OBJECT_HANDLE, SECStatus};

pub type CERTCertList = CERTCertListStr;
pub type CERTCertListNode = CERTCertListNodeStr;
pub type CERTCertificate = CERTCertificateStr;
pub type CERTSignedData = CERTSignedDataStr;
pub type CERTName = CERTNameStr;
pub type CERTRDN = CERTRDNStr;
pub type CERTAVA = CERTAVAStr;
pub type CERTValidity = CERTValidityStr;
pub type CERTSubjectPublicKeyInfo = CERTSubjectPublicKeyInfoStr;
pub type CERTCertExtension = CERTCertExtensionStr;
pub type CERTCertDBHandle = NSSTrustDomainStr;
pub type CERTOKDomainName = CERTOKDomainNameStr;
pub type CERTCertTrust = CERTCertTrustStr;
pub type CERTSubjectList = CERTSubjectListStr;
pub type CERTSubjectNode = CERTSubjectNodeStr;
pub type CERTAuthKeyID = CERTAuthKeyIDStr;
pub type CERTGeneralName = CERTGeneralNameStr;

#[derive(Debug)]
#[repr(C)]
pub struct CERTCertListStr {
    pub list: PRCList,
    pub arena: *mut PLArenaPool,
}

#[derive(Debug)]
#[repr(C)]
pub struct CERTCertListNodeStr {
    pub links: PRCList,
    pub cert: *mut CERTCertificate,
    pub appData: *mut c_void,
}

#[derive(Debug)]
#[repr(C)]
pub struct CERTCertificateStr {
    pub arena: *mut PLArenaPool,
    pub subjectName: *mut c_char,
    pub issuerName: *mut c_char,
    pub signatureWrap: CERTSignedData,
    pub derCert: SECItem,
    pub derIssuer: SECItem,
    pub derSubject: SECItem,
    pub derPublicKey: SECItem,
    pub certKey: SECItem,
    pub version: SECItem,
    pub serialNumber: SECItem,
    pub signature: SECAlgorithmID,
    pub issuer: CERTName,
    pub validity: CERTValidity,
    pub subject: CERTName,
    pub subjectPublicKeyInfo: CERTSubjectPublicKeyInfo,
    pub issuerID: SECItem,
    pub subjectID: SECItem,
    pub extensions: *mut *mut CERTCertExtension,
    pub emailAddr: *mut c_char,
    pub dbhandle: *mut CERTCertDBHandle,
    pub subjectKeyID: SECItem,
    pub keyIDGenerated: PRBool,
    pub keyUsage: c_uint,
    pub rawKeyUsage: c_uint,
    pub keyUsagePresent: PRBool,
    pub nsCertType: PRUint32,
    pub keepSession: PRBool,
    pub timeOK: PRBool,
    pub domainOK: *mut CERTOKDomainName,
    pub isperm: PRBool,
    pub istemp: PRBool,
    pub nickname: *mut c_char,
    pub dbnickname: *mut c_char,
    pub nssCertificate: *mut NSSCertificateStr,
    pub trust: *mut CERTCertTrust,
    pub referenceCount: c_int,
    pub subjectList: *mut CERTSubjectList,
    pub authKeyID: *mut CERTAuthKeyID,
    pub isRoot: PRBool,
    // In C, `options` is a union of a `void*` and an `unsigned int : 1` bitfield.
    // The comment also indicates that it's used only be "the browser" and
    // not by NSS itself, so exposing it in detail may not be necessary.
    pub options: usize,
    pub series: c_int,
    pub slot: *mut PK11SlotInfo,
    pub pkcs11ID: CK_OBJECT_HANDLE,
    pub ownSlot: PRBool,
}

#[derive(Debug)]
#[repr(C)]
pub struct CERTSignedDataStr {
    pub data: SECItem,
    pub signatureAlgorithm: SECAlgorithmID,
    pub signature: SECItem,
}

#[derive(Debug)]
#[repr(C)]
pub struct CERTNameStr {
    pub arena: *mut PLArenaPool,
    pub rdns: *mut *mut CERTRDN,
}

#[derive(Debug)]
#[repr(C)]
pub struct CERTRDNStr {
    pub avas: *mut *mut CERTAVA,
}

#[derive(Debug)]
#[repr(C)]
pub struct CERTAVAStr {
    pub type_: SECItem,
    pub value: SECItem,
}

#[derive(Debug)]
#[repr(C)]
pub struct CERTValidityStr {
    pub arena: *mut PLArenaPool,
    pub notBefore: SECItem,
    pub notAfter: SECItem,
}

#[derive(Debug)]
#[repr(C)]
pub struct CERTSubjectPublicKeyInfoStr {
    pub arena: *mut PLArenaPool,
    pub algorithm: SECAlgorithmID,
    pub subjectPublicKey: SECItem,
}

#[derive(Debug)]
#[repr(C)]
pub struct CERTCertExtensionStr {
    pub id: SECItem,
    pub critical: SECItem,
    pub value: SECItem,
}

#[derive(Debug)]
#[repr(C)]
pub struct CERTOKDomainNameStr {
    pub next: *mut CERTOKDomainName,
    // Actually a variable-length array (null-terminated), but can't
    // use an unsized `[c_char]` in Rust because that would make raw
    // pointers to this struct have an extra length word, which is
    // wrong.  This is good enough for reading the string (getting the
    // address, calling `strlen`, and creating a slice); if Rust code
    // needs to construct one of these then that might need raw
    // pointer arithmetic.
    pub name0: c_char,
}

#[derive(Debug)]
#[repr(C)]
// This might need some accompanying enums....
pub struct CERTCertTrustStr {
    pub sslFlags: c_uint,
    pub emailFlags: c_uint,
    pub objectSigningFlags: c_uint,
}

#[derive(Debug)]
#[repr(C)]
pub struct CERTSubjectListStr {
    pub arena: *mut PLArenaPool,
    pub ncerts: c_int,
    pub emailAddr: *mut c_char,
    pub head: *mut CERTSubjectNode,
    pub tail: *mut CERTSubjectNode,
    pub entry: *mut c_void,
}

#[derive(Debug)]
#[repr(C)]
pub struct CERTSubjectNodeStr {
    pub next: *mut CERTSubjectNodeStr,
    pub prev: *mut CERTSubjectNodeStr,
    pub certKey: SECItem,
    pub keyID: SECItem,
}

#[derive(Debug)]
#[repr(C)]
pub struct CERTAuthKeyIDStr {
    pub keyID: SECItem,
    pub authCertIssuer: *mut CERTGeneralName,
    pub authCertSerialNumber: SECItem,
    pub DERAuthCertIssuer: *mut *mut SECItem,
}

// FIXME -- has union
pub enum CERTGeneralNameStr { }

extern "C" {
    pub fn CERT_DestroyCertificate(cert: *mut CERTCertificate);
    pub fn CERT_DestroyCertList(cert: *mut CERTCertList);
    pub fn CERT_VerifyCertName(cert: *const CERTCertificate, hn: *const c_char) -> SECStatus;
}
