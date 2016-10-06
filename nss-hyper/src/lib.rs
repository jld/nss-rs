extern crate hyper;
extern crate nss;
extern crate nss_webpki;
extern crate time;

use hyper::net::{NetworkStream, SslClient};
use nss::{File, FileMethods, FileWrapper, TLSSocket, BorrowedTLSSocket, AuthCertificateHook,
          TLSCipherSuite, TLS_VERSION_1_0, SSL_ENABLE_SESSION_TICKETS};
use nss::error::{PR_NOT_CONNECTED_ERROR, SSL_ERROR_UNKNOWN_CIPHER_SUITE};
use nss::nspr::fd::PR_DESC_SOCKET_TCP;
use nss_webpki::{TrustConfig, MOZILLA_ANCHORS, ALL_SIG_ALGS};
use time::get_time;

use std::any::Any;
use std::borrow::Borrow;
use std::ffi::CString;
use std::io;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct NssClient<N: NetworkStream = hyper::net::HttpStream> {
    factory: FileWrapper<StreamToFile<N>>,
}

impl<N: NetworkStream> NssClient<N> {
    pub fn new() -> Self {
        nss::init().unwrap(); // FIXME don't use unwrap
        NssClient {
            factory: FileWrapper::new(PR_DESC_SOCKET_TCP),
        }
    }
}

macro_rules! nss_try {
    ($e:expr) => { try!($e.map_err(Into::<io::Error>::into)) }
}

// Copied from Firefox 52.
const MODERN_CRYPTO: &'static [TLSCipherSuite] = &[
    // FIXME: should the TLS 1.3 draft AEAD stuff go here?
    nss::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    nss::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    nss::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    nss::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    nss::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    nss::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    nss::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    nss::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    nss::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    nss::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    nss::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    nss::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    // These last 3 are deprecated (so not really "modern") -- non-DHE
    // means no forward secrecy, and attacks on 3DES are starting to
    // become practical.
    nss::TLS_RSA_WITH_AES_128_CBC_SHA,
    nss::TLS_RSA_WITH_AES_256_CBC_SHA,
    nss::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
];

fn limit_ciphersuites<Cb>(sock: &mut TLSSocket<Cb>, suites: &[TLSCipherSuite]) -> nss::Result<()> {
    // Turn everything off.
    for &suite in TLSCipherSuite::implemented() {
        try!(sock.set_ciphersuite_enabled(suite, false));
    }
    // Then turn on the ones we want.
    for &suite in suites {
        try!(match sock.set_ciphersuite_enabled(suite, true) {
            Err(e) if e.nspr_error == SSL_ERROR_UNKNOWN_CIPHER_SUITE => Ok(()),
            other => other,
        })
    }
    Ok(())
}

impl<N: NetworkStream + Clone> SslClient<N> for NssClient<N> {
    type Stream = FileToStream<TLSSocket<NSSCallbacks>>;

    fn wrap_client(&self, mut stream: N, host: &str) -> hyper::error::Result<Self::Stream> {
        let peer_addr = try!(stream.peer_addr());
        let backend = StreamToFile::new(stream);
        let inner = self.factory.wrap(backend);
        let callbacks = NSSCallbacks { host_name: CString::new(host).unwrap() };
        let mut outer = nss_try!(TLSSocket::new(inner, callbacks));
        // FIXME: should this be in an `on_register` method or someting?
        nss_try!(outer.set_url(&outer.callbacks().host_name));
        nss_try!(outer.use_auth_certificate_hook());
        // This "connect" just fixes NSS's state; handshake isn't sent until first write.
        nss_try!(outer.connect(peer_addr, None));
        // Modernize the security setup.
        // TODO: Make this configurable somehow, with reasonable defaults -- maybe
        // a "TLS config" object, and/or could be a callback to use NSS APIs directly.
        // TODO: ...and extend that to controlling the webpki config; will need that
        // for real-world revocation checking if nothing else.
        nss_try!(outer.limit_version(Some(TLS_VERSION_1_0), None));
        nss_try!(outer.set_option(SSL_ENABLE_SESSION_TICKETS, true));
        nss_try!(limit_ciphersuites(&mut outer, MODERN_CRYPTO));
        Ok(FileToStream::new(outer))
    }
}

pub struct NSSCallbacks {
    host_name: CString
}
impl AuthCertificateHook for NSSCallbacks {
    fn auth_certificate(&self, sock: BorrowedTLSSocket<Self>, check_sig: bool, is_server: bool)
                        -> nss::Result<()> {
        assert!(check_sig);
        assert!(!is_server);
        // FIXME don't panic
        let chain = sock.peer_cert_chain().expect("server didn't present certificates!");
        let tcfg = TrustConfig {
            anchors: MOZILLA_ANCHORS,
            sig_algs: ALL_SIG_ALGS,
        };
        tcfg.verify(&chain, self.host_name.as_bytes(), get_time())
    }
}

pub struct StreamToFile<N: NetworkStream> {
    inner: Mutex<StreamToFileInner<N>>,
}

struct StreamToFileInner<N: NetworkStream> {
    stream: N,
    timeouts: Timeouts,
    connected: bool,
}

struct Timeouts {
    read: Option<Duration>,
    write: Option<Duration>,
}
impl Timeouts {
    fn new() -> Self {
        Timeouts {
            read: None,
            write: None,
        }
    }
}

impl<N: NetworkStream> StreamToFile<N> {
    pub fn new(stream: N) -> Self {
        StreamToFile {
            inner: Mutex::new(StreamToFileInner {
                stream: stream,
                timeouts: Timeouts::new(),
                connected: false,
            })
        }
    }
}

impl<N: NetworkStream> FileMethods for StreamToFile<N> {
    // FIXME: do I even need `read` and `write`?
    fn read(&self, buf: &mut [u8]) -> nss::Result<usize> {
        self.recv(buf, false, None)
    }
    fn write(&self, buf: &[u8]) -> nss::Result<usize> {
        self.send(buf, None)
    }

    fn connect(&self, _addr: SocketAddr, _timeout: Option<Duration>) -> nss::Result<()> {
        let mut this = self.inner.lock().unwrap();
        this.connected = true;
        Ok(())
    }

    fn recv(&self, buf: &mut [u8], peek: bool, timeout: Option<Duration>) -> nss::Result<usize> {
        if peek {
            unimplemented!()
        }
        let mut this = self.inner.lock().unwrap();
        if this.timeouts.read != timeout {
            try!(this.stream.set_read_timeout(timeout));
            this.timeouts.read = timeout
        }
        Ok(try!(this.stream.read(buf)))
    }

    fn send(&self, buf: &[u8], timeout: Option<Duration>) -> nss::Result<usize> {
        let mut this = self.inner.lock().unwrap();
        if this.timeouts.write != timeout {
            try!(this.stream.set_write_timeout(timeout));
            this.timeouts.write = timeout
        }
        Ok(try!(this.stream.write(buf)))
    }

    fn getpeername(&self) -> nss::Result<SocketAddr> {
        let mut this = self.inner.lock().unwrap();
        if this.connected {
            this.stream.peer_addr().map_err(Into::into)
        } else {
            Err(PR_NOT_CONNECTED_ERROR.into())
        }
    }

    fn get_nonblocking(&self) -> nss::Result<bool> {
        Ok(false)
    }
}


pub struct FileToStream<F>
    where F: Borrow<File> + Send + Sync + Any
{
    // This Arc is because network streams need to be Clone... because
    // they're like file descriptors, I guess?  But what does that
    // mean for stateful streams like TLS?  Is this actually the right
    // Clone behavior?
    inner: Arc<FileToStreamInner<F>>,
}

// Can't derive this because derive insists the type param be Clone
// even though that doesn't matter because Arc.  Sigh.
impl<F> Clone for FileToStream<F>
    where F: Borrow<File> + Send + Sync + Any
{
    fn clone(&self) -> Self {
        FileToStream { inner: self.inner.clone() }
    }
}

struct FileToStreamInner<F>
    where F: Borrow<File> + Send + Sync + Any
{
    file: F,
    // This Mutex is because the timeouts are changed by &self methods,
    // which sort of makes sense as being like `setsockopt` on a file
    // descriptor... but `peer_addr` takes &mut self so ???.
    timeouts: Mutex<Timeouts>,
}

impl<F> FileToStream<F>
    where F: Borrow<File> + Send + Sync + Any
{
    pub fn new(file: F) -> Self {
        FileToStream {
            inner: Arc::new(FileToStreamInner {
                file: file,
                timeouts: Mutex::new(Timeouts::new()),
            })
        }
    }
}

impl<F> Read for FileToStream<F>
    where F: Borrow<File> + Send + Sync + Any
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let timeout = self.inner.timeouts.lock().unwrap().read;
        // Is there some reason why try! insists on From instead of the weaker bound Into?
        self.inner.file.borrow().recv(buf, false, timeout).map_err(Into::into)
    }
}

impl<F> Write for FileToStream<F>
    where F: Borrow<File> + Send + Sync + Any
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let timeout = self.inner.timeouts.lock().unwrap().write;
        self.inner.file.borrow().send(buf, timeout).map_err(Into::into)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<F> NetworkStream for FileToStream<F>
    where F: Borrow<File> + Send + Sync + Any
{
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.inner.file.borrow().getpeername().map_err(Into::into)
    }
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.timeouts.lock().unwrap().read = dur;
        Ok(())
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.timeouts.lock().unwrap().write = dur;
        Ok(())
    }
    // TODO: map NetworkStream::close() to PR_Shutdown?
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
