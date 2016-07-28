use libc::c_int;
use nss_sys::nspr as sys;
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
            Err(Error::last())
        } else {
            Ok(Self::from_raw_prfd(fd))
        }
    }

    pub fn new_tcp_socket(af: c_int) -> Result<Self> {
        super::init();
        unsafe { Self::from_raw_prfd_err(sys::PR_OpenTCPSocket(af)) }
    }
    pub fn new_udp_socket(af: c_int) -> Result<Self> {
        super::init();
        unsafe { Self::from_raw_prfd_err(sys::PR_OpenUDPSocket(af)) }
    }
}

fn null() -> RawFile { ptr::null_mut() }

#[cfg(test)]
mod tests {
    use super::*;
    use libc::AF_INET;

    #[test]
    fn drop_tcp() {
        let _fd = File::new_tcp_socket(AF_INET).unwrap();
    }

    #[test]
    fn drop_udp() {
        let _fd = File::new_udp_socket(AF_INET).unwrap();
    }
}
