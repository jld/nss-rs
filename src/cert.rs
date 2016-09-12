use nss_sys as ffi;
use super::sec_item_as_slice;
use std::mem;
use std::ptr;

pub struct Certificate(*mut ffi::CERTCertificate);

impl Certificate {
    pub unsafe fn from_raw_ptr(ptr: *mut ffi::CERTCertificate) -> Self {
        assert!(ptr != ptr::null_mut());
        Certificate(ptr)
    }
    pub unsafe fn from_raw_ptr_opt(ptr: *mut ffi::CERTCertificate) -> Option<Self> {
        if ptr == ptr::null_mut() {
            None
        } else {
            Some(Self::from_raw_ptr(ptr))
        }
    }
    pub fn into_raw_ptr(self) -> *mut ffi::CERTCertificate {
        let ptr = self.as_raw_ptr();
        mem::forget(self);
        ptr
    }
    pub fn as_raw_ptr(&self) -> *mut ffi::CERTCertificate {
        debug_assert!(self.0 != ptr::null_mut());
        self.0
    }
    pub fn as_ffi_ref(&self) -> &ffi::CERTCertificate {
        unsafe { mem::transmute(self.as_raw_ptr()) }
    }

    pub fn as_der(&self) -> &[u8] {
        unsafe {
            sec_item_as_slice(&self.as_ffi_ref().derCert)
        }
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        let ptr = mem::replace(&mut self.0, ptr::null_mut());
        if ptr != ptr::null_mut() {
            unsafe { ffi::CERT_DestroyCertificate(ptr) }
        }
    }
}
