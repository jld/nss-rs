use nss_sys::nspr as sys;
use std::mem;
use std::ptr;

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
}

fn null() -> RawFile { ptr::null_mut() }
