/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use nss_sys as ffi;
use super::{sec_item_as_slice, wrap_ffi, Result};
use nspr::{ListNode, Listable, ListIterator};
use std::ffi::CStr;
use std::marker::PhantomData;
use std::mem;
use std::ops::Deref;
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
        let ptr = self.0;
        debug_assert!(ptr != ptr::null_mut());
        mem::forget(self);
        ptr
    }
    pub fn as_raw_ptr(&self) -> *const ffi::CERTCertificate {
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

    pub fn verify_name(&self, host_name: &CStr) -> Result<()> {
        wrap_ffi(|| unsafe {
            ffi::CERT_VerifyCertName(self.as_raw_ptr(), host_name.as_ptr())
        })
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

pub struct BorrowedCertificate<'a>(*mut ffi::CERTCertificate, PhantomData<&'a Certificate>);

impl<'a> Listable for BorrowedCertificate<'a> {
    unsafe fn from_list_node(list: ListNode) -> Self {
        let node = list as *mut ffi::CERTCertListNode;
        BorrowedCertificate((*node).cert, PhantomData)
    }
}

impl<'a> Deref for BorrowedCertificate<'a> {
    type Target = Certificate;
    fn deref(&self) -> &Certificate {
        unsafe {
            mem::transmute(self)
        }
    }
}

impl<'a> BorrowedCertificate<'a> {
    // Extend the lifetime a little:
    // (FIXME: should Certificate deref to BorrowedCertificate<'self> instead?)
    pub fn as_der(&self) -> &'a [u8] {
        unsafe { mem::transmute(Certificate::as_der(self)) }
    }
}

pub struct CertList(*mut ffi::CERTCertList);

impl CertList {
    pub unsafe fn from_raw_ptr(ptr: *mut ffi::CERTCertList) -> Self {
        assert!(ptr != ptr::null_mut());
        CertList(ptr)
    }
    pub unsafe fn from_raw_ptr_opt(ptr: *mut ffi::CERTCertList) -> Option<Self> {
        if ptr == ptr::null_mut() {
            None
        } else {
            Some(Self::from_raw_ptr(ptr))
        }
    }
    pub fn iter(&self) -> ListIterator<BorrowedCertificate> {
        self.into_iter()
    }
}

impl Drop for CertList {
    fn drop(&mut self) {
        let ptr = mem::replace(&mut self.0, ptr::null_mut());
        if ptr != ptr::null_mut() {
            unsafe { ffi::CERT_DestroyCertList(ptr) }
        }
    }
}

impl<'a> IntoIterator for &'a CertList {
    type Item = BorrowedCertificate<'a>;
    type IntoIter = ListIterator<'a, Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        unsafe {
            ListIterator::new(&(*self.0).list as *const _ as ListNode)
        }
    }
}

// Could also do a consuming iterator on CertList that unlinks and frees nodes as it goes.
// But I don't think anything actually needs that.
