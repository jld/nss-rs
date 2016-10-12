# NSS Bindings for Rust

This is a very incomplete project for enabling Rust code to use the
[NSS][] cryptography library.  Currently it exposes only the minimum
needed to be a simple TLS client, and is almost completely lacking in
documentation.

Other crates in this repository:

* [nss-sys](nss-sys) defines low-level bindings that directly reflect the C code.

* [nss-webpki](nss-webpki) is a simple wrapper for the `webpki` crate,
  for verifying certificate lists obtained through NSS.  (NSS's own
  certificate verification code is old and doesn't follow modern best
  practices.)

* [nss-hyper](nss-hyper) implements the `SslClient` trait for the
  `hyper` HTTP library, using NSS (with webpki for certificate
  verification).  It has an example program (`client`) that makes HTTPS
  requests to URLs given as arguments and writes the result to `stdout`.

[NSS]: https://nss-crypto.org/
