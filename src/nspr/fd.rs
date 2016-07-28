use libc::{c_int, c_void};
use nss_sys::nspr as ffi;
use std::ffi::CString;
use std::i32;
use std::marker::PhantomData;
use std::mem;
use std::ops::Deref;
use std::ptr;
use std::sync::Arc;
use ::Error;
use ::Result;

pub type RawFile = *mut ffi::PRFileDesc;

pub struct File(RawFile);
unsafe impl Send for File { }
unsafe impl Sync for File { }

impl Drop for File {
    fn drop(&mut self) {
        let fd = mem::replace(&mut self.0, null());
        if fd != null() {
            let _status = unsafe { ffi::PR_Close(fd) };
        }
    }
}

// Should any/all of these be `pub`?
#[allow(dead_code)]
impl File {
    fn into_raw_prfd(self) -> RawFile {
        let fd = self.as_raw_prfd();
        mem::forget(self);
        fd
    }
    fn as_raw_prfd(&self) -> RawFile {
        debug_assert!(self.0 != null());
        self.0
    }
    unsafe fn from_raw_prfd(fd: RawFile) -> Self {
        assert!(fd != null());
        File(fd)
    }
    unsafe fn from_raw_prfd_opt(fd: RawFile) -> Option<Self> {
        if fd == null() {
            None
        } else {
            Some(Self::from_raw_prfd(fd))
        }
    }
    unsafe fn from_raw_prfd_err(fd: RawFile) -> Result<Self> {
        if fd == null() {
            failed()
        } else {
            Ok(Self::from_raw_prfd(fd))
        }
    }

    // Should these be in a different module?  (Or here at all?)
    pub fn new_tcp_socket(af: c_int) -> Result<Self> {
        super::init();
        unsafe { Self::from_raw_prfd_err(ffi::PR_OpenTCPSocket(af)) }
    }
    pub fn new_udp_socket(af: c_int) -> Result<Self> {
        super::init();
        unsafe { Self::from_raw_prfd_err(ffi::PR_OpenUDPSocket(af)) }
    }
    pub fn new_pipe() -> Result<(File, File)> {
        super::init();
        let mut reader = null();
        let mut writer = null();
        unsafe {
            match ffi::PR_CreatePipe(&mut reader, &mut writer) {
                ffi::PR_SUCCESS => Ok((Self::from_raw_prfd(reader),
                                  Self::from_raw_prfd(writer))),
                ffi::PR_FAILURE => failed()
            }
        }
    }
}

fn null() -> RawFile { ptr::null_mut() }
fn failed<T>() -> Result<T> { Err(Error::last()) }

pub trait FileMethods {
    fn read(&self, _buf: &mut [u8]) -> Result<usize> { unimplemented!() }
    fn write(&self, _buf: &[u8]) -> Result<usize> { unimplemented!() }
}

impl FileMethods for File {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        assert!(buf.len() <= i32::MAX as usize);
        result_of_len32(unsafe {
            ffi::PR_Read(self.as_raw_prfd(), buf.as_mut_ptr() as *mut c_void, buf.len() as i32)
        })
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        assert!(buf.len() <= i32::MAX as usize);
        result_of_len32(unsafe {
            ffi::PR_Write(self.as_raw_prfd(), buf.as_ptr() as *const c_void, buf.len() as i32)
        })
    }
}

fn result_of_len32(rv: i32) -> Result<usize> {
    if rv >= 0 {
        Ok(rv as usize)
    } else {
        failed()
    }
}

pub type FileType = ffi::PRDescType;
pub use nss_sys::nspr::{PR_DESC_FILE, PR_DESC_SOCKET_TCP, PR_DESC_SOCKET_UDP, PR_DESC_LAYERED,
                        PR_DESC_PIPE};

pub struct FileWrapper<Inner>
    where Inner: FileMethods + Send + Sync {
    methods_ref: Arc<ffi::PRIOMethods>,
    phantom: PhantomData<Fn(Inner)>,
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
            connect: None,
            accept: None,
            bind: None,
            listen: None,
            shutdown: None,
            recv: None,
            send: None,
            recvfrom: None,
            sendto: None,
            poll: None,
            acceptread: None,
            transmitfile: None,
            getsockname: None,
            getpeername: None,
            reserved_fn_6: None,
            reserved_fn_5: None,
            getsocketoption: None,
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

    pub fn wrap(&self, inner: Inner) -> File {
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
    use nss_sys::nspr::{PRFileDesc, PRStatus, PR_SUCCESS, PRInt32};
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
    use libc::AF_INET;
    use std::mem;

    #[test]
    fn drop_tcp() {
        let _fd = File::new_tcp_socket(AF_INET).unwrap();
    }

    #[test]
    fn drop_udp() {
        let _fd = File::new_udp_socket(AF_INET).unwrap();
    }

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
