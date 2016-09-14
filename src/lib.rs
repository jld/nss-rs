#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate nss_sys;
pub mod nspr;
pub mod cert;

use libc::c_void;
use nss_sys as ffi;
use std::borrow::Borrow;
use std::ffi::CStr;
use std::mem;
use std::ops::{Deref,DerefMut};
use std::ptr;
use std::slice;

pub use nspr::error::{Error, Result, failed, PR_WOULD_BLOCK_ERROR};
pub use nspr::fd::{File, FileMethods, FileWrapper};
pub use cert::{Certificate, CertList};
use nspr::fd::{RawFile, BorrowedFile};
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

// This is a newtype so that it can have traits on it.
pub struct TLSSocket<Callbacks>(Box<TLSSocketImpl<Callbacks>>);
// This isn't a newtype so that Deref etc. can return it.
pub type BorrowedTLSSocket<'a, Callbacks> = &'a TLSSocketImpl<Callbacks>;

pub struct TLSSocketImpl<Callbacks> {
    file: File,
    callbacks: Callbacks,
}

impl<Callbacks> Deref for TLSSocket<Callbacks> {
    type Target = TLSSocketImpl<Callbacks>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<Callbacks> DerefMut for TLSSocket<Callbacks> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl<Callbacks> Deref for TLSSocketImpl<Callbacks> {
    type Target = File;
    fn deref(&self) -> &File {
        &self.file
    }
}
// DerefMut would be unsound -- could shuffle sockets holding pointers to callbacks

// So that there's a type inhabited by both File and TLSSocket<_>.
impl<Callbacks> Borrow<File> for TLSSocket<Callbacks> {
    fn borrow(&self) -> &File {
        self
    }
}

impl<Callbacks> TLSSocket<Callbacks> {
    pub fn new(inner: File, callbacks: Callbacks) -> Result<Self> {
        Self::new_with_model(inner, callbacks, None)
    }
    pub fn new_with_model(inner: File, callbacks: Callbacks, model: Option<Self>) -> Result<Self>
    {
        if let Some(_) = model {
            // This will copy the callbacks; need to unset or fix them.
            unimplemented!();
        }
        let raw_model = model.map_or(nspr::fd::null(), |fd| fd.as_raw_prfd());
        unsafe {
            let raw = ffi::SSL_ImportFD(raw_model, inner.as_raw_prfd());
            let file = try!(File::from_raw_prfd_err(raw));
            mem::forget(inner);
            Ok(TLSSocket(Box::new(TLSSocketImpl {
                file: file,
                callbacks: callbacks,
            })))
        }
    }

    pub fn use_auth_certificate_hook(&mut self) -> Result<()>
        where Callbacks: AuthCertificateHook
    {
        let this: BorrowedTLSSocket<_> = &*self;
        result_secstatus(unsafe {
            ffi::SSL_AuthCertificateHook(self.as_raw_prfd(),
                                         Some(raw_auth_certificate_hook::<Callbacks>),
                                         mem::transmute(this))
        })
    }
}

impl<Callbacks> TLSSocketImpl<Callbacks> {
    pub fn callbacks(&self) -> &Callbacks {
        &self.callbacks
    }
    // callbacks_mut would be sound, but would anything use it?

    pub fn peer_cert(&self) -> Option<Certificate> {
        unsafe { 
            Certificate::from_raw_ptr_opt(ffi::SSL_PeerCertificate(self.as_raw_prfd()))
        }
    }

    pub fn peer_cert_chain(&self) -> Option<CertList> {
        unsafe {
            CertList::from_raw_ptr_opt(ffi::SSL_PeerCertificateChain(self.as_raw_prfd()))
        }
    }

    pub fn cleartext(&self) -> BorrowedFile {
        unsafe {
            BorrowedFile::from_raw_prfd((*self.as_raw_prfd()).lower)
        }
    }

    pub fn set_url(&self, url: &CStr) -> Result<()> {
        result_secstatus(unsafe {
            ffi::SSL_SetURL(self.as_raw_prfd(), url.as_ptr())
        })
    }

    pub fn unset_bad_cert_hook(&mut self) -> Result<()> {
        // This doesn't take locks in the C code, so needs a unique ref.
        result_secstatus(unsafe {
            ffi::SSL_BadCertHook(self.as_raw_prfd(), None, ptr::null_mut())
        })
    }

    pub fn unset_auth_certificate_hook(&mut self) -> Result<()> {
        result_secstatus(unsafe {
            ffi::SSL_AuthCertificateHook(self.as_raw_prfd(), None, ptr::null_mut())
        })
    }

    // FIXME: turn this into an actual callback now that that's possible?
    pub fn disable_security(&mut self) -> Result<()> {
        unsafe extern "C" fn this_is_fine(_arg: *mut c_void, _fd: RawFile) -> ffi::SECStatus {
            ffi::SECSuccess
        }
        result_secstatus(unsafe {
            ffi::SSL_BadCertHook(self.as_raw_prfd(), Some(this_is_fine), ptr::null_mut())
        })
    }
}

pub trait AuthCertificateHook: Sized {
    fn auth_certificate(&self, sock: BorrowedTLSSocket<Self>, check_sig: bool, is_server: bool)
                        -> Result<()>;
}

unsafe extern "C" fn raw_auth_certificate_hook<Callbacks>(arg: *mut c_void,
                                                          fd: *mut ffi::nspr::PRFileDesc,
                                                          check_sig: ffi::nspr::PRBool,
                                                          is_server: ffi::nspr::PRBool)
                                                          -> ffi::SECStatus
    where Callbacks: AuthCertificateHook
{
    // TODO: check identity?
    let this: BorrowedTLSSocket<Callbacks> = mem::transmute(arg);
    assert_eq!(this.as_raw_prfd(), fd);
    match this.callbacks.auth_certificate(this,
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
        let ssl = TLSSocket::new(sock, ()).unwrap();
        ssl.connect(fake_addr(), None).unwrap();
        assert_eq!(ssl.write(&[]).unwrap_err().nspr_error, PR_END_OF_FILE_ERROR);
        println!("DATA: {:?}", &buf.lock().unwrap()[..]);
    }
}
