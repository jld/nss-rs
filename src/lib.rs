#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate nss_sys;
pub mod nspr;

use libc::c_void;
use nss_sys as ffi;
use std::marker::PhantomData;
use std::mem;
use std::ptr;

pub use nspr::error::{Error, Result, failed, PR_WOULD_BLOCK_ERROR};
pub use nspr::fd::{File,FileMethods,FileWrapper};
use nspr::fd::RawFile;

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

pub struct TLSMarker<Inner>(PhantomData<Inner>);
// As long as the NSPR bindings are in the same crate, doing this as a
// type equation still allows adding impls/inherents; otherwise it
// would need to be a newtype with a bunch of conversion traits.
pub type TLSSocket<Inner> = File<TLSMarker<Inner>>;

impl<Inner> TLSSocket<Inner> {
    pub fn new(inner: File<Inner>) -> Result<Self> {
        Self::new_with_model(inner, None::<Self>)
    }
    pub fn new_with_model<Other>(inner: File<Inner>,
                                 model: Option<TLSSocket<Other>>) -> Result<Self>
    {
        let raw_model = model.map_or(nspr::fd::null(), |fd| fd.as_raw_prfd());
        unsafe {
            let raw = ffi::SSL_ImportFD(raw_model, inner.as_raw_prfd());
            let sock = try!(File::from_raw_prfd_err(raw));
            mem::forget(inner);
            Ok(sock)
        }
    }

    pub fn unset_bad_cert_hook(&mut self) -> Result<()> {
        // This doesn't take locks in the C code, so needs a unique ref.
        result_secstatus(unsafe {
            ffi::SSL_BadCertHook(self.as_raw_prfd(), None, ptr::null_mut())
        })
    }

    pub fn disable_security(&mut self) -> Result<()> {
        unsafe extern "C" fn this_is_fine(_arg: *mut c_void, _fd: RawFile) -> ffi::SECStatus {
            ffi::SECSuccess
        }
        result_secstatus(unsafe {
            ffi::SSL_BadCertHook(self.as_raw_prfd(), Some(this_is_fine), ptr::null_mut())
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use nspr::error::{PR_NOT_CONNECTED_ERROR, PR_IS_CONNECTED_ERROR, PR_END_OF_FILE_ERROR};
    use std::net::{SocketAddr,SocketAddrV4,Ipv4Addr};
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[test]
    fn just_init() {
        init().unwrap();
    }

    #[test]
    fn handshake() {
        fn fake_addr() -> SocketAddr {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443))
        }

        struct FakeSocket {
            connected: AtomicBool,
            written: Arc<Mutex<Vec<u8>>>,
        }

        impl FakeSocket {
            fn new() -> Self {
                FakeSocket {
                    connected: AtomicBool::new(false),
                    written: Arc::new(Mutex::new(Vec::new())),
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
            fn send(&self, buf: &[u8], _timeout: Option<Duration>) -> Result<usize> {
                self.write(buf)
            }
            fn recv(&self, buf: &mut [u8], _peek: bool, _timeout: Option<Duration>) -> Result<usize>
            {
                self.read(buf)
            }
            fn getpeername(&self) -> Result<SocketAddr> {
                if self.connected.load(Ordering::SeqCst) {
                    Ok(fake_addr())
                } else {
                    Err(PR_NOT_CONNECTED_ERROR.into())
                }
            }
            fn connect(&self, addr: SocketAddr, _timeout: Option<Duration>) -> Result<()> {
                assert_eq!(addr, fake_addr());
                if self.connected.swap(true, Ordering::SeqCst) {
                    // Shouldn't be used but might as well:
                    Err(PR_IS_CONNECTED_ERROR.into())
                } else {
                    Ok(())
                }
            }
        }

        init().unwrap();
        let inner = FakeSocket::new();
        let buf = inner.written.clone();
        let sock_factory = FileWrapper::new(nspr::fd::PR_DESC_SOCKET_TCP);
        let sock = sock_factory.wrap(inner);
        let ssl = TLSSocket::new(sock).unwrap();
        ssl.connect(fake_addr(), None).unwrap();
        assert_eq!(ssl.write(&[]).unwrap_err().nspr_error, PR_END_OF_FILE_ERROR);
        println!("DATA: {:?}", &buf.lock().unwrap()[..]);
    }
}
