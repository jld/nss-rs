extern crate nss;
extern crate time;
extern crate untrusted;
extern crate webpki;

mod tmp_anchors;

use nss::CertList;
use time::Timespec;
use untrusted::Input;
use webpki::{Error, TrustAnchor, EndEntityCert, SignatureAlgorithm};

pub struct TrustConfig<'a> {
    pub anchors: &'a [TrustAnchor<'a>],
    pub sig_algs: &'a [&'a SignatureAlgorithm],
    // TODO: collection of additional (dis)trust info
}

impl<'a> TrustConfig<'a> {
    pub fn verify(&self, certs: &CertList, dns_name: &[u8], time: Timespec) -> Result<(), Error> {
        let mut iter = certs.iter();
        // FIXME overloading BadDER is not quite right.
        let ee_der = try!(iter.next().ok_or(Error::BadDER)).as_der();
        let end_entity = try!(EndEntityCert::from(Input::from(ee_der)));
        let intermediates: Vec<_> = iter.map(|cert| Input::from(cert.as_der())).collect();
        try!(end_entity.verify_is_valid_tls_server_cert(self.sig_algs, self.anchors,
                                                        &intermediates, time));
        end_entity.verify_is_valid_for_dns_name(Input::from(dns_name))
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

pub use tmp_anchors::TRUST_ANCHORS as TMP_ANCHORS;

// TODO: translate webpki errors to NSS/NSPR errors

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let _tc = TrustConfig {
            anchors: TMP_ANCHORS,
            sig_algs: ALL_SIG_ALGS,
        };
    }
}
