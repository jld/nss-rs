use libc::{c_int, c_void};
use nss_sys::nspr as sys;
use std::i32;
use std::mem;
use std::ptr;
use ::Result;
use ::Error;

pub type RawFile = *mut sys::PRFileDesc;

pub struct File(RawFile);
unsafe impl Send for File { }
unsafe impl Sync for File { }

impl Drop for File {
    fn drop(&mut self) {
        let fd = mem::replace(&mut self.0, null());
        if fd != null() {
            let _status = unsafe { sys::PR_Close(fd) };
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

    unsafe fn get_private<T: Send + Sync>(&self) -> *mut T {
        (*self.as_raw_prfd()).secret as *mut T
    }
    unsafe fn set_private<T: Send + Sync>(&mut self, ptr: *mut T) {
        (*self.as_raw_prfd()).secret = ptr as *mut sys::PRFilePrivate
    }

    // Should these be in a different module?  (Or here at all?)
    pub fn new_tcp_socket(af: c_int) -> Result<Self> {
        super::init();
        unsafe { Self::from_raw_prfd_err(sys::PR_OpenTCPSocket(af)) }
    }
    pub fn new_udp_socket(af: c_int) -> Result<Self> {
        super::init();
        unsafe { Self::from_raw_prfd_err(sys::PR_OpenUDPSocket(af)) }
    }
    pub fn new_pipe() -> Result<(File, File)> {
        super::init();
        let mut reader = null();
        let mut writer = null();
        unsafe {
            match sys::PR_CreatePipe(&mut reader, &mut writer) {
                sys::PR_SUCCESS => Ok((Self::from_raw_prfd(reader),
                                  Self::from_raw_prfd(writer))),
                sys::PR_FAILURE => failed()
            }
        }
    }
}

fn null() -> RawFile { ptr::null_mut() }
fn failed<T>() -> Result<T> { Err(Error::last()) }

trait FileMethods {
    fn read(&self, buf: &mut [u8]) -> Result<usize>;
    fn write(&self, buf: &[u8]) -> Result<usize>;
}

impl FileMethods for File {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        assert!(buf.len() <= i32::MAX as usize);
        result_of_len32(unsafe {
            sys::PR_Read(self.as_raw_prfd(), buf.as_mut_ptr() as *mut c_void, buf.len() as i32)
        })
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        assert!(buf.len() <= i32::MAX as usize);
        result_of_len32(unsafe {
            sys::PR_Write(self.as_raw_prfd(), buf.as_ptr() as *const c_void, buf.len() as i32)
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

#[cfg(test)]
mod tests {
    use super::*;
    use super::FileMethods;
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

    #[test]
    fn pipe_rdwr() {
        static TEST: &'static str = "Testing…";
        let (reader, writer) = File::new_pipe().unwrap();
        assert_eq!(writer.write(TEST.as_bytes()).unwrap(), TEST.len());

        let mut read_buf = vec![0u8; TEST.len()];
        assert_eq!(reader.read(&mut read_buf[..4]).unwrap(), 4);
        assert_eq!(&read_buf[..4], "Test".as_bytes());
        assert_eq!(reader.read(&mut read_buf[4..]).unwrap(), TEST.len() - 4);
        assert_eq!(read_buf, TEST.as_bytes());
        mem::drop(writer);
        assert_eq!(reader.read(&mut read_buf).unwrap(), 0);
    }
}
