use libc::c_void;
use nss_sys::nspr as ffi;
use std::ffi::CString;
use std::i32;
use std::marker::PhantomData;
use std::mem;
use std::net::SocketAddr;
use std::ops::Deref;
use std::ptr;
use std::sync::Arc;
use std::time::Duration;
use nspr::{result_len32, result_prstatus, bool_from_nspr};
use nspr::error::{Result, failed, PR_ADDRESS_NOT_SUPPORTED_ERROR};
use nspr::net::{NetAddrStorage, read_net_addr, write_net_addr};
use nspr::time::duration_opt_to_nspr;

pub type RawFile = *mut ffi::PRFileDesc;

pub struct File(RawFile);
unsafe impl Send for File { }
unsafe impl Sync for File { }

impl Drop for File {
    fn drop(&mut self) {
        let fd = mem::replace(&mut self.0, null());
        if fd != null() {
            // FIXME: this can deadlock in case of panic while holding NSPR locks
            // (e.g., NSS with panic in Rust-implemented lower layer)
            let _status = unsafe { ffi::PR_Close(fd) };
        }
    }
}

#[allow(dead_code)]
impl File {
    pub fn into_raw_prfd(self) -> RawFile {
        let fd = self.as_raw_prfd();
        mem::forget(self);
        fd
    }
    pub fn as_raw_prfd(&self) -> RawFile {
        debug_assert!(self.0 != null());
        self.0
    }
    pub unsafe fn from_raw_prfd(fd: RawFile) -> Self {
        assert!(fd != null());
        File(fd)
    }
    pub unsafe fn from_raw_prfd_opt(fd: RawFile) -> Option<Self> {
        if fd == null() {
            None
        } else {
            Some(Self::from_raw_prfd(fd))
        }
    }
    pub unsafe fn from_raw_prfd_err(fd: RawFile) -> Result<Self> {
        if fd == null() {
            failed()
        } else {
            Ok(Self::from_raw_prfd(fd))
        }
    }

    pub fn new_pipe() -> Result<(File, File)> {
        super::init();
        let mut reader = null();
        let mut writer = null();
        unsafe {
            try!(result_prstatus(ffi::PR_CreatePipe(&mut reader, &mut writer)));
            Ok((Self::from_raw_prfd(reader), Self::from_raw_prfd(writer)))
        }
    }
}

pub fn null() -> RawFile { ptr::null_mut() }

pub trait FileMethods {
    fn read(&self, _buf: &mut [u8]) -> Result<usize> {
        unimplemented!()
    }
    fn write(&self, _buf: &[u8]) -> Result<usize> {
        unimplemented!()
    }
    fn connect(&self, _addr: SocketAddr, _timeout: Option<Duration>) -> Result<()> {
        unimplemented!()
    }
    // FIXME: use a special enum for peek, not bool.
    fn recv(&self, _buf: &mut [u8], _peek: bool, _timeout: Option<Duration>) -> Result<usize> {
        unimplemented!()
    }
    fn send(&self, _buf: &[u8], _timeout: Option<Duration>) -> Result<usize> {
        unimplemented!()
    }
    fn getsockname(&self) -> Result<SocketAddr> {
        unimplemented!()
    }
    fn getpeername(&self) -> Result<SocketAddr> {
        unimplemented!()
    }
    fn get_nonblocking(&self) -> Result<bool> {
        unimplemented!()
    }
}

impl FileMethods for File {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        assert!(buf.len() <= i32::MAX as usize);
        result_len32(unsafe {
            ffi::PR_Read(self.as_raw_prfd(), buf.as_mut_ptr() as *mut c_void, buf.len() as i32)
        })
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        assert!(buf.len() <= i32::MAX as usize);
        result_len32(unsafe {
            ffi::PR_Write(self.as_raw_prfd(), buf.as_ptr() as *const c_void, buf.len() as i32)
        })
    }

    fn connect(&self, addr: SocketAddr, timeout: Option<Duration>) -> Result<()> {
        let mut addrbuf = NetAddrStorage::new();
        result_prstatus(unsafe {
            write_net_addr(addrbuf.as_mut_ptr(), addr);
            ffi::PR_Connect(self.as_raw_prfd(), addrbuf.as_ptr(), duration_opt_to_nspr(timeout))
        })
    }

    fn recv(&self, buf: &mut [u8], peek: bool, timeout: Option<Duration>) -> Result<usize> {
        assert!(buf.len() <= i32::MAX as usize);
        let flags = if peek { ffi::PR_MSG_PEEK } else { 0 };
        result_len32(unsafe {
            ffi::PR_Recv(self.as_raw_prfd(), buf.as_mut_ptr() as *mut c_void, buf.len() as i32,
                         flags, duration_opt_to_nspr(timeout))
        })
    }

    fn send(&self, buf: &[u8], timeout: Option<Duration>) -> Result<usize> {
        assert!(buf.len() <= i32::MAX as usize);
        let flags = 0;
        result_len32(unsafe {
            ffi::PR_Send(self.as_raw_prfd(), buf.as_ptr() as *const c_void, buf.len() as i32,
                         flags, duration_opt_to_nspr(timeout))
        })
    }

    fn getsockname(&self) -> Result<SocketAddr> {
        let mut buf = NetAddrStorage::new();
        try!(result_prstatus(unsafe {
            ffi::PR_GetSockName(self.as_raw_prfd(), buf.as_mut_ptr())
        }));
        match unsafe { read_net_addr(buf.as_ptr()) } {
            Some(addr) => Ok(addr),
            None => Err(PR_ADDRESS_NOT_SUPPORTED_ERROR.into()),
        }
    }

    fn getpeername(&self) -> Result<SocketAddr> {
        let mut buf = NetAddrStorage::new();
        try!(result_prstatus(unsafe {
            ffi::PR_GetPeerName(self.as_raw_prfd(), buf.as_mut_ptr())
        }));
        match unsafe { read_net_addr(buf.as_ptr()) } {
            Some(addr) => Ok(addr),
            None => Err(PR_ADDRESS_NOT_SUPPORTED_ERROR.into()),
        }
    }

    fn get_nonblocking(&self) -> Result<bool> {
        type OptCase = ffi::PRSocketOptionCase<ffi::PRBool>;
        let mut buf = OptCase::new(ffi::PR_SockOpt_Nonblocking, ffi::PR_FALSE);
        try!(result_prstatus(unsafe {
            ffi::PR_GetSocketOption(self.as_raw_prfd(), buf.as_mut_ptr())
        }));
        Ok(bool_from_nspr(buf.value))
    }
}

pub type FileType = ffi::PRDescType;
pub use nss_sys::nspr::{PR_DESC_FILE, PR_DESC_SOCKET_TCP, PR_DESC_SOCKET_UDP, PR_DESC_LAYERED,
                        PR_DESC_PIPE};

pub struct FileWrapper<Inner>
    where Inner: FileMethods + Send + Sync {
    methods_ref: Arc<ffi::PRIOMethods>,
    phantom: PhantomData<fn(Inner)>,
}

struct WrappedFile<Inner>
    where Inner: FileMethods + Send + Sync {
    prfd: ffi::PRFileDesc,
    _methods_ref: Arc<ffi::PRIOMethods>,
    inner: Inner,
}

impl<Inner> FileWrapper<Inner> where Inner: FileMethods + Send + Sync {
    pub fn new(file_type: FileType) -> Self {
        let methods = ffi::PRIOMethods {
            file_type: file_type,
            close: Some(wrapper_methods::close::<Inner>),
            read: Some(wrapper_methods::read::<Inner>),
            write: Some(wrapper_methods::write::<Inner>),
            available: None,
            available64: None,
            fsync: None,
            seek: None,
            seek64: None,
            fileInfo: None,
            fileInfo64: None,
            writev: None,
            connect: Some(wrapper_methods::connect::<Inner>),
            accept: None,
            bind: None,
            listen: None,
            shutdown: None,
            recv: Some(wrapper_methods::recv::<Inner>),
            send: Some(wrapper_methods::send::<Inner>),
            recvfrom: None,
            sendto: None,
            poll: None,
            acceptread: None,
            transmitfile: None,
            getsockname: Some(wrapper_methods::getsockname::<Inner>),
            getpeername: Some(wrapper_methods::getpeername::<Inner>),
            reserved_fn_6: None,
            reserved_fn_5: None,
            getsocketoption: Some(wrapper_methods::getsocketoption::<Inner>),
            setsocketoption: None,
            sendfile: None,
            connectcontinue: None,
            reserved_fn_3: None,
            reserved_fn_2: None,
            reserved_fn_1: None,
            reserved_fn_0: None,
        };

        FileWrapper {
            methods_ref: Arc::new(methods),
            phantom: PhantomData,
        }
    }

    // FIXME: should the 'static be higher?
    // FIXME: should File<> be parameterized to allow non-'static backends?
    // (That would also allow non-Sync backends....)
    pub fn wrap(&self, inner: Inner) -> File where Inner: 'static {
        let methods_raw = self.methods_ref.deref() as *const _;
        let mut boxed = Box::new(WrappedFile {
            prfd: ffi::PRFileDesc {
                methods: methods_raw,
                secret: ptr::null_mut(),
                lower: ptr::null_mut(),
                higher: ptr::null_mut(),
                dtor: None,
                identity: *WRAPPED_FILE_IDENT,
            },
            _methods_ref: self.methods_ref.clone(),
            inner: inner
        });
        unsafe {
            let raw = &mut boxed.prfd as RawFile;
            (*raw).secret = Box::into_raw(boxed) as *mut ffi::PRFilePrivate;
            File::from_raw_prfd(raw)
        }
    }
}

mod wrapper_methods {
    use super::{FileMethods, WrappedFile, WRAPPED_FILE_IDENT};
    use libc::c_void;
    use nss_sys::nspr::{PRFileDesc, PRNetAddr, PRStatus, PRInt32, PRIntn, PRIntervalTime, PRBool,
                        PRSocketOptionData, PRSocketOptionCase, PR_SockOpt_Nonblocking,
                        PR_SUCCESS, PR_FAILURE, PR_MSG_PEEK};
    use nspr::bool_to_nspr;
    use nspr::error::PR_ADDRESS_NOT_SUPPORTED_ERROR;
    use nspr::net::{read_net_addr, write_net_addr};
    use nspr::time::duration_opt_from_nspr;
    use std::mem;
    use std::slice;

    unsafe fn get_raw_secret<Inner>(fd: *mut PRFileDesc) -> *mut WrappedFile<Inner>
        where Inner: FileMethods + Send + Sync
    {
        assert_eq!((*fd).identity, *WRAPPED_FILE_IDENT);
        (*fd).secret as *mut WrappedFile<Inner>
    }
    unsafe fn get_secret<'a, Inner>(fd: *mut PRFileDesc) -> &'a WrappedFile<Inner>
        where Inner: FileMethods + Send + Sync
    {
        mem::transmute(get_raw_secret::<Inner>(fd))
    }

    pub unsafe extern "C" fn close<Inner>(fd: *mut PRFileDesc) -> PRStatus
        where Inner: FileMethods + Send + Sync
    {
        let this = get_raw_secret::<Inner>(fd);
        // Ensure that, whatever in-place linked list node swapping
        // happened during this object's lifetime due to I/O layering,
        // its contents are now back where they started and we can
        // safely free the box.  (This condition will generally *not*
        // be true in other methods.)
        assert_eq!(&mut (*this).prfd as *mut _, fd);
        mem::drop(Box::from_raw(this));
        PR_SUCCESS
    }

    pub unsafe extern "C" fn read<Inner>(fd: *mut PRFileDesc,
                                     buf: *mut c_void,
                                     amount: PRInt32) -> PRInt32
        where Inner: FileMethods + Send + Sync
    {
        let this = get_secret::<Inner>(fd);
        assert!(amount >= 0);
        match this.inner.read(slice::from_raw_parts_mut(buf as *mut u8, amount as usize)) {
            Ok(len) => { assert!(len <= amount as usize); len as PRInt32 },
            Err(err) => { err.set(); -1 }
        }
    }

    pub unsafe extern "C" fn write<Inner>(fd: *mut PRFileDesc,
                                          buf: *const c_void,
                                          amount: PRInt32) -> PRInt32
        where Inner: FileMethods + Send + Sync
    {
        let this = get_secret::<Inner>(fd);
        assert!(amount >= 0);
        match this.inner.write(slice::from_raw_parts(buf as *mut u8, amount as usize)) {
            Ok(len) => { assert!(len <= amount as usize); len as PRInt32 },
            Err(err) => { err.set(); -1 }
        }
    }

    pub unsafe extern "C" fn connect<Inner>(fd: *mut PRFileDesc,
                                            addr: *const PRNetAddr,
                                            timeout: PRIntervalTime) -> PRStatus
        where Inner: FileMethods + Send + Sync
    {
        let this = get_secret::<Inner>(fd);
        let status = if let Some(rust_addr) = read_net_addr(addr) {
            this.inner.connect(rust_addr, duration_opt_from_nspr(timeout))
        } else {
            Err(PR_ADDRESS_NOT_SUPPORTED_ERROR.into())
        };
        match status {
            Ok(()) => PR_SUCCESS,
            Err(err) => { err.set(); PR_FAILURE },
        }
    }

    pub unsafe extern "C" fn recv<Inner>(fd: *mut PRFileDesc,
                                         buf: *mut c_void,
                                         amount: PRInt32,
                                         flags: PRIntn,
                                         timeout: PRIntervalTime) -> PRInt32
        where Inner: FileMethods + Send + Sync
    {
        let this = get_secret::<Inner>(fd);
        assert!(amount >= 0);
        let peek = flags & PR_MSG_PEEK != 0;
        match this.inner.recv(slice::from_raw_parts_mut(buf as *mut u8, amount as usize),
                              peek, duration_opt_from_nspr(timeout)) {
            Ok(len) => { assert!(len <= amount as usize); len as PRInt32 },
            Err(err) => { err.set(); -1 }
        }
    }

    pub unsafe extern "C" fn send<Inner>(fd: *mut PRFileDesc,
                                         buf: *const c_void,
                                         amount: PRInt32,
                                         _flags: PRIntn,
                                         timeout: PRIntervalTime) -> PRInt32
        where Inner: FileMethods + Send + Sync
    {
        let this = get_secret::<Inner>(fd);
        assert!(amount >= 0);
        match this.inner.send(slice::from_raw_parts(buf as *mut u8, amount as usize),
                              duration_opt_from_nspr(timeout)) {
            Ok(len) => { assert!(len <= amount as usize); len as PRInt32 },
            Err(err) => { err.set(); -1 }
        }
    }

    pub unsafe extern "C" fn getsockname<Inner>(fd: *mut PRFileDesc,
                                                addr: *mut PRNetAddr) -> PRStatus
        where Inner: FileMethods + Send + Sync
    {
        let this = get_secret::<Inner>(fd);
        match this.inner.getsockname() {
            Ok(rust_addr) => { write_net_addr(addr, rust_addr); PR_SUCCESS },
            Err(err) => { err.set(); PR_FAILURE },
        }
    }

    pub unsafe extern "C" fn getpeername<Inner>(fd: *mut PRFileDesc,
                                                addr: *mut PRNetAddr) -> PRStatus
        where Inner: FileMethods + Send + Sync
    {
        let this = get_secret::<Inner>(fd);
        match this.inner.getpeername() {
            Ok(rust_addr) => { write_net_addr(addr, rust_addr); PR_SUCCESS },
            Err(err) => { err.set(); PR_FAILURE },
        }
    }

    pub unsafe extern "C" fn getsocketoption<Inner>(fd: *mut PRFileDesc,
                                                    data: *mut PRSocketOptionData) -> PRStatus
        where Inner: FileMethods + Send + Sync
    {
        let this = get_secret::<Inner>(fd);
        match (*data).get_enum() {
            PR_SockOpt_Nonblocking => {
                let data = data as *mut PRSocketOptionCase<PRBool>;
                match this.inner.get_nonblocking() {
                    Ok(b) => { (*data).value = bool_to_nspr(b); PR_SUCCESS },
                    Err(err) => { err.set(); PR_FAILURE },
                }
            }
            _ => unimplemented!()
        }
    }
}

lazy_static! {
    static ref WRAPPED_FILE_IDENT: ffi::PRDescIdentity = {
        super::init();
        let name = CString::new("Rust").unwrap();
        unsafe { ffi::PR_GetUniqueIdentity(name.as_ptr()) }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    fn pipe_test(reader: File, writer: File) {
        static TEST: &'static str = "Testing…";

        assert_eq!(writer.write(TEST.as_bytes()).unwrap(), TEST.len());
        let mut read_buf = vec![0u8; TEST.len()];
        assert_eq!(reader.read(&mut read_buf[..4]).unwrap(), 4);
        assert_eq!(&read_buf[..4], "Test".as_bytes());
        assert_eq!(reader.read(&mut read_buf[4..]).unwrap(), TEST.len() - 4);
        assert_eq!(read_buf, TEST.as_bytes());
        mem::drop(writer);
        assert_eq!(reader.read(&mut read_buf).unwrap(), 0);
    }

    #[test]
    fn pipe_rdwr() {
        let (reader, writer) = File::new_pipe().unwrap();
        pipe_test(reader, writer);
    }

    #[test]
    fn wrapped_pipe_rdwr() {
        let wrapper = FileWrapper::new(PR_DESC_PIPE);
        let (reader, writer) = File::new_pipe().unwrap();
        pipe_test(wrapper.wrap(reader), wrapper.wrap(writer));
    }

    #[test]
    fn very_wrapped_pipe_rdwr() {
        let wrapper = FileWrapper::new(PR_DESC_PIPE);
        let (mut reader, mut writer) = File::new_pipe().unwrap();
        for _ in 0..100 {
            reader = wrapper.wrap(reader);
            writer = wrapper.wrap(writer);
        }
        pipe_test(reader, writer);
    }
}
