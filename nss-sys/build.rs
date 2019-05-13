/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */
extern crate bindgen;

use std::env;
use std::path::PathBuf;

use bindgen::RustTarget;
use bindgen::callbacks::{ParseCallbacks, IntKind};

fn is_prefix(name: &str, prefix: &str) -> bool {
    name.len() >= prefix.len() && &name[..prefix.len()] == prefix
}

#[derive(Debug)]
struct NSSTypes;

impl ParseCallbacks for NSSTypes {
    fn int_macro(&self, name: &str, _value: i64) -> Option<IntKind> {
        if is_prefix(name, "SSL_LIBRARY_VERSION_") {
            return Some(IntKind::U16)
        }
        if is_prefix(name, "PR_MSG_") {
            return Some(IntKind::I32)
        }
        if is_prefix(name, "CKF_") {
            // This should be typed CK_FLAGS
            // on amd64: u64, may be u32 on 32bit, not sure, have to check
            return Some(IntKind::U64)
        }
        if is_prefix(name, "CKR_") {
            // This should be typed CK_RV
            // on amd64: u64, may be u32 on 32bit, not sure, have to check
            return Some(IntKind::U64)
        }
        if is_prefix(name, "CKM_") {
            // This should be typed CK_MECHANISM_TYPE
            // on amd64: u64, may be u32 on 32bit, not sure, have to check
            return Some(IntKind::U64)
        }
        if is_prefix(name, "CKA_") {
            // This should be typed CK_ATTRIBUTE_TYPE
            // on amd64: u64, may be u32 on 32bit, not sure, have to check
            return Some(IntKind::U64)
        }
        if is_prefix(name, "CKD_") {
            // This should be typed CK_EC_KDF_TYPE
            // on amd64: u64, may be u32 on 32bit, not sure, have to check
            return Some(IntKind::U64)
        }
        if is_prefix(name, "CKK_") {
            // This should be typed CK_KEY_TYPE
            // on amd64: u64, may be u32 on 32bit, not sure, have to check
            return Some(IntKind::U64)
        }
        if is_prefix(name, "PK11_") {
            // This should be typed PK11AttrFlags
            return Some(IntKind::U32)
        }
        if is_prefix(name, "SEC_ASN1_OBJECT_ID") {
            return Some(IntKind::U8)
        }

        if name == "PR_FALSE" || name == "PR_TRUE" {
            return Some(IntKind::I32)
        }
        None
    }
}

fn base_builder() -> bindgen::Builder {
    bindgen::Builder::default()
        // Do not generate unstable Rust code that
        // requires a nightly rustc and enabling
        // unstable features.
        .rust_target(RustTarget::Stable_1_19)
        // include
        .clang_arg("-I/usr/include/nspr")
        .clang_arg("-I/usr/include/nss")
        .parse_callbacks(Box::new(NSSTypes{}))
}

fn main() {
    println!("cargo:rustc-link-lib=nss3");
    println!("cargo:rustc-link-lib=ssl3");
    println!("cargo:rustc-link-lib=nspr4");

    // Write the bindings to the $OUT_DIR/*.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    base_builder()
        // The input header we would like to generate
        // bindings for.
        .header("wrappers/nss.h")
        // Whitelist
        .whitelist_type("PK11_.*")
        .whitelist_type("SEC.*")
        .whitelist_type("SSL.*")
        .whitelist_type("CERT.*")
        .whitelist_type("CKF_.*")
        .whitelist_type("SECOID_.*")
        .whitelist_type("ECCurve.*")
        .whitelist_type("SEC_.*")
        .whitelist_type("CK_.*")
        .whitelist_var("NSS_.*")
        .whitelist_var("SSL_.*")
        .whitelist_var("TLS_.*")
        .whitelist_var("SRTP_.*")
        .whitelist_var("CERT_.*")
        .whitelist_var("CKA_.*")
        .whitelist_var("CKD_.*")
        .whitelist_var("CKF_.*")
        .whitelist_var("CKK_.*")
        .whitelist_var("CKM_.*")
        .whitelist_var("CKO_.*")
        .whitelist_var("CKR_.*")
        .whitelist_var("ECCurve.*")
        .whitelist_var("SEC_.*")
        .whitelist_var("PK11_.*")
        .whitelist_function("PK11_.*")
        .whitelist_function("SSL_.*")
        .whitelist_function("CERT_.*")
        .whitelist_function("NSS_.*")
        .whitelist_function("SECOID_.*")
        .whitelist_function("SECITEM_.*")
        .whitelist_function("PORT_.*")
        .rustified_enum("_SEC.*")
        .rustified_enum("SEC.*")
        .rustified_enum("SSL.*")
        .rustified_enum("CKF.*")
        .blacklist_type("PR.*")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("nss.rs"))
        .expect("Couldn't write bindings!");

    base_builder()
        // The input header we would like to generate
        // bindings for.
        .header("wrappers/nspr.h")
        // Whitelist
        .whitelist_type("PR.*")
        .whitelist_var("PR_.*")
        .whitelist_function("PR_.*")
        .rustified_enum("PR.*")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("nspr.rs"))
        .expect("Couldn't write bindings!");

}
