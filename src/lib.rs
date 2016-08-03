#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate nss_sys;
pub mod nspr;

use nss_sys as ffi;
use std::mem;
use std::ptr;
use std::ops::Deref;

pub use nspr::error::{Error, Result, failed, PR_WOULD_BLOCK_ERROR};
pub use nspr::fd::{File,FileMethods,FileWrapper};

fn result_secstatus(status: ffi::SECStatus) -> Result<()> {
    // Must call this immediately after the NSS operation so that the
    // thread-local error state isn't stale.
    match status {
        ffi::SECSuccess => Ok(()),
        ffi::SECFailure => failed(),
        ffi::SECWouldBlock => Err(PR_WOULD_BLOCK_ERROR.into()),
    }
}

// TODO: What do I do about this init/shutdown stuff vs. lifetimes/safety?

pub fn init() -> Result<()> {
    nspr::init();
    result_secstatus(unsafe { ffi::NSS_NoDB_Init(ptr::null()) })
}

pub struct TLSSocket(File);
impl Deref for TLSSocket {
    type Target = File;
    fn deref(&self) -> &File { &self.0 }
}
impl TLSSocket {
    pub fn new(inner: File) -> Result<Self> {
        Self::new_with_model(inner, None)
    }
    pub fn new_with_model(inner: File, model: Option<Self>) -> Result<Self> {
        let raw_model = model.map_or(nspr::fd::null(), |fd| fd.as_raw_prfd());
        unsafe {
            let raw = ffi::SSL_ImportFD(raw_model, inner.as_raw_prfd());
            let sock = try!(File::from_raw_prfd_err(raw));
            mem::forget(inner);
            Ok(TLSSocket(sock))
        }
    }
    pub fn into_file(self) -> File { self.0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr,SocketAddrV4,Ipv4Addr};
    use std::sync::{Arc, Mutex};

    #[test]
    fn just_init() {
        init().unwrap();
    }

    #[test]
    fn handshake() {
        struct FakeSocket {
            written: Arc<Mutex<Vec<u8>>>
        }

        impl FakeSocket {
            fn new() -> Self {
                FakeSocket {
                    written: Arc::new(Mutex::new(Vec::new()))
                }
            }
        }

        impl FileMethods for FakeSocket {
            fn read(&self, _buf: &mut[u8]) -> Result<usize> {
                Ok(0)
            }

            fn write(&self, buf: &[u8]) -> Result<usize> {
                self.written.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn getpeername(&self) -> Result<SocketAddr> {
                Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443)))
            }
        }

        let inner = FakeSocket::new();
        let buf = inner.written.clone();
        let sock_factory = FileWrapper::new(nspr::fd::PR_DESC_SOCKET_TCP);
        let sock = sock_factory.wrap(inner);
        let _ssl = TLSSocket::new(sock).unwrap();
        // let _ = ssl.write(&[0x41]);
        // println!("{} BEES", buf.lock().unwrap().len());
    }
}
