#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate nss_sys;
pub mod nspr;
pub mod cert;

use libc::c_void;
use nss_sys as ffi;
use std::ffi::CStr;
use std::marker::PhantomData;
use std::mem;
use std::ptr;
use std::slice;

pub use nspr::error::{Error, Result, failed, PR_WOULD_BLOCK_ERROR};
pub use nspr::fd::{File, FileMethods, FileWrapper};
pub use cert::Certificate;
use nspr::fd::{RawFile, BorrowedFile, WrappedFileImpl};
use nspr::bool_from_nspr;

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

// Caller must ensure this isn't one of the SECItems where the length
// is actually bits instead of bytes.
pub unsafe fn sec_item_as_slice(item: &ffi::SECItem) -> &[u8] {
    slice::from_raw_parts(item.data, item.len as usize)
}

pub struct TLSMarker<Inner>(PhantomData<Inner>);
// As long as the NSPR bindings are in the same crate, doing this as a
// type equation still allows adding impls/inherents; otherwise it
// would need to be a newtype with a bunch of conversion traits.
pub type TLSSocket<Inner> = File<TLSMarker<Inner>>;

impl<Inner> TLSSocket<Inner> {
    pub fn new(inner: File<Inner>) -> Result<Self> {
        Self::new_with_model(inner, None)
    }
    pub fn new_with_model(inner: File<Inner>, model: Option<Self>) -> Result<Self>
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

    pub fn peer_cert(&self) -> Option<Certificate> {
        unsafe { 
            Certificate::from_raw_ptr_opt(ffi::SSL_PeerCertificate(self.as_raw_prfd()))
        }
    }

    pub fn cleartext(&self) -> BorrowedFile<Inner> {
        unsafe {
            BorrowedFile::from_raw_prfd((*self.as_raw_prfd()).lower)
        }
    }

    pub fn use_auth_certificate_hook(&mut self) -> Result<()>
        where Inner: AuthCertificateHook<Inner>
    {
        result_secstatus(unsafe {
            ffi::SSL_AuthCertificateHook(self.as_raw_prfd(),
                                         Some(raw_auth_certificate_hook::<Inner>),
                                         ptr::null_mut())
        })
    }

    pub fn set_url(&self, url: &CStr) -> Result<()> {
        result_secstatus(unsafe {
            ffi::SSL_SetURL(self.as_raw_prfd(), url.as_ptr())
        })
    }
}

pub trait AuthCertificateHook<Inner> {
    fn auth_certificate(&self, sock: &TLSSocket<Inner>, check_sig: bool, is_server: bool)
        -> Result<()>;
}

impl<Inner, MoreInner> AuthCertificateHook<Inner> for WrappedFileImpl<MoreInner>
    where MoreInner: FileMethods + AuthCertificateHook<Inner>
{
    fn auth_certificate(&self, socket: &TLSSocket<Inner>, check_sig: bool, is_server: bool)
        -> Result<()>
    {
        MoreInner::auth_certificate(self, socket, check_sig, is_server)
    }
}

unsafe extern "C" fn raw_auth_certificate_hook<Inner>(_arg: *mut c_void,
                                                      fd: *mut ffi::nspr::PRFileDesc,
                                                      check_sig: ffi::nspr::PRBool,
                                                      is_server: ffi::nspr::PRBool)
                                                      -> ffi::SECStatus
    where Inner: AuthCertificateHook<Inner>
{
    // TODO: check identity?
    let sock: BorrowedFile<TLSMarker<Inner>> = BorrowedFile::from_raw_prfd_ref(&fd);
    match sock.cleartext().get_ref().auth_certificate(&sock,
                                                      bool_from_nspr(check_sig),
                                                      bool_from_nspr(is_server)) {
        Ok(()) => ffi::SECSuccess,
        Err(err) => { err.set(); ffi::SECFailure }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nspr::error::{PR_NOT_CONNECTED_ERROR, PR_IS_CONNECTED_ERROR, PR_END_OF_FILE_ERROR};
    use std::net::{SocketAddr,SocketAddrV4,Ipv4Addr};
    use std::cell::{Cell,RefCell};
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

        struct FakeSocket<'a> {
            connected: Cell<bool>,
            written: RefCell<&'a mut Vec<u8>>,
        }

        impl<'a> FakeSocket<'a> {
            fn new(buf: &'a mut Vec<u8>) -> Self {
                FakeSocket {
                    connected: Cell::new(false),
                    written: RefCell::new(buf),
                }
            }
        }

        impl<'a> FileMethods for FakeSocket<'a> {
            fn read(&self, _buf: &mut[u8]) -> Result<usize> {
                Ok(0)
            }
            fn write(&self, buf: &[u8]) -> Result<usize> {
                self.written.borrow_mut().extend_from_slice(buf);
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
                if self.connected.get() {
                    Ok(fake_addr())
                } else {
                    Err(PR_NOT_CONNECTED_ERROR.into())
                }
            }
            fn connect(&self, addr: SocketAddr, _timeout: Option<Duration>) -> Result<()> {
                assert_eq!(addr, fake_addr());
                if self.connected.get() {
                    // Shouldn't be used but might as well:
                    Err(PR_IS_CONNECTED_ERROR.into())
                } else {
                    self.connected.set(true);
                    Ok(())
                }
            }
        }

        init().unwrap();
        let mut buf = Vec::new();
        {
            let inner = FakeSocket::new(&mut buf);
            let sock_factory = FileWrapper::new(nspr::fd::PR_DESC_SOCKET_TCP);
            let sock = sock_factory.wrap(inner);
            let ssl = TLSSocket::new(sock).unwrap();
            ssl.connect(fake_addr(), None).unwrap();
            assert_eq!(ssl.write(&[]).unwrap_err().nspr_error, PR_END_OF_FILE_ERROR);
        }
        println!("DATA: {:?}", buf);
    }
}
