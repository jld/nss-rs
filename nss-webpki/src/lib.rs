extern crate mozilla_ca_certs;
extern crate nss;
extern crate time;
extern crate untrusted;
extern crate webpki;

use nss::{CertList,Result,error};
use time::Timespec;
use untrusted::Input;
use webpki::Error as WebPKIError;
use webpki::{TrustAnchor, EndEntityCert, SignatureAlgorithm};

pub struct TrustConfig<'a> {
    pub anchors: &'a [TrustAnchor<'a>],
    pub sig_algs: &'a [&'a SignatureAlgorithm],
    // TODO: collection of additional (dis)trust info
}

fn err_map(wpe: WebPKIError) -> error::ErrorCode {
    match wpe {
        WebPKIError::BadDER => error::SEC_ERROR_BAD_DER,
        WebPKIError::BadDERTime => error::SEC_ERROR_INVALID_TIME,
        WebPKIError::CAUsedAsEndEntity => error::SEC_ERROR_CERT_USAGES_INVALID, // ???
        WebPKIError::CertExpired => error::SEC_ERROR_EXPIRED_CERTIFICATE,
        WebPKIError::CertNotValidForName => error::SSL_ERROR_BAD_CERT_DOMAIN, // ???
        WebPKIError::CertNotValidYet => error::SEC_ERROR_EXPIRED_CERTIFICATE,
        WebPKIError::EndEntityUsedAsCA => error::SEC_ERROR_CA_CERT_INVALID,
        WebPKIError::ExtensionValueInvalid => error::SEC_ERROR_EXTENSION_VALUE_INVALID,
        WebPKIError::InvalidCertValidity => error::SEC_ERROR_CERT_NOT_VALID, // ...
        WebPKIError::InvalidReferenceName => error::SSL_ERROR_BAD_CERT_DOMAIN, // ???
        WebPKIError::InvalidSignatureForPublicKey => error::SEC_ERROR_BAD_SIGNATURE,
        WebPKIError::NameConstraintViolation => error::SEC_ERROR_CERT_NOT_IN_NAME_SPACE, // ???
        WebPKIError::PathLenConstraintViolated => error::SEC_ERROR_PATH_LEN_CONSTRAINT_INVALID,
        WebPKIError::SignatureAlgorithmMismatch => error::SEC_ERROR_BAD_SIGNATURE, // ???
        WebPKIError::RequiredEKUNotFound => error::SEC_ERROR_INADEQUATE_KEY_USAGE, // ???
        WebPKIError::UnknownIssuer => error::SEC_ERROR_UNKNOWN_ISSUER,
        WebPKIError::UnsupportedCertVersion => error::SEC_ERROR_CERT_NOT_VALID, // ...
        WebPKIError::UnsupportedCriticalExtension => error::SEC_ERROR_UNKNOWN_CRITICAL_EXTENSION,
        WebPKIError::UnsupportedSignatureAlgorithmForPublicKey
            => error::SEC_ERROR_INVALID_ALGORITHM, // ...
        WebPKIError::UnsupportedSignatureAlgorithm
            => error::SEC_ERROR_INVALID_ALGORITHM, // ...
    }
}

macro_rules! webpki_try {
    ($e:expr) => { try!($e.map_err(err_map)) }
}

impl<'a> TrustConfig<'a> {
    pub fn verify(&self, certs: &CertList, dns_name: &[u8], time: Timespec) -> Result<()> {
        let mut iter = certs.iter();
        let ee_der = try!(iter.next().ok_or(error::SSL_ERROR_NO_CERTIFICATE)).as_der();
        let end_entity = webpki_try!(EndEntityCert::from(Input::from(ee_der)));
        let intermediates: Vec<_> = iter.map(|cert| Input::from(cert.as_der())).collect();
        webpki_try!(end_entity.verify_is_valid_tls_server_cert(self.sig_algs, self.anchors,
                                                               &intermediates, time));
        webpki_try!(end_entity.verify_is_valid_for_dns_name(Input::from(dns_name)));
        Ok(())
    }
}

pub static ALL_SIG_ALGS: &'static [&'static SignatureAlgorithm] = &[
    // Reasonable algorithms.
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,

    // Algorithms deprecated because they are nonsensical combinations.
    &webpki::ECDSA_P256_SHA384, // Truncates digest.
    &webpki::ECDSA_P256_SHA512, // Truncates digest.
    &webpki::ECDSA_P384_SHA256, // Digest is unnecessarily short.
    &webpki::ECDSA_P384_SHA512, // Truncates digest.

    // Algorithms deprecated because they are bad.
    &webpki::RSA_PKCS1_2048_8192_SHA1, // SHA-1
    &webpki::ECDSA_P256_SHA1, // SHA-1
    &webpki::ECDSA_P384_SHA1, // SHA-1
];

pub static GOOD_SIG_ALGS: &'static [&'static SignatureAlgorithm] = &[
    // Reasonable algorithms.
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
];

pub use mozilla_ca_certs::WEBPKI_TRUST_ROOTS as MOZILLA_ANCHORS;

// TODO: translate webpki errors to NSS/NSPR errors

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let _tc = TrustConfig {
            anchors: MOZILLA_ANCHORS,
            sig_algs: ALL_SIG_ALGS,
        };
    }
}
