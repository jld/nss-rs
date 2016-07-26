fn main() {
    println!("cargo:rustc-link-lib=nss3");
    println!("cargo:rustc-link-lib=ssl3");
    println!("cargo:rustc-link-lib=nspr4");
}
