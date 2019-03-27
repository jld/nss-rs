/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)] // for CK_STUFF; could lower if cryptoki becomes a submodule
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/nspr.rs"));

// This represents a PRSocketOptionData for a specific actual type of
// the value union.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PRSocketOptionCase<T> {
    // This should be the same size as the enum + the alignment padding
    // before the union.
    padded_enum: PRSize,
    pub value: T
}
impl<T> PRSocketOptionCase<T> {
    pub fn new(which: PRSockOption, value: T) -> Self {
        let mut padded_enum: PRSize = 0;
        // Write the discriminant to the start of the space occupied by padded_enum.
        unsafe { *(&mut padded_enum as *mut PRSize as *mut PRSockOption) = which; }
        PRSocketOptionCase {
            padded_enum: padded_enum,
            value: value
        }
    }
    pub fn get_enum(&self) -> PRSockOption {
        // Read the discriminant from the start of the space occupied by padded_enum.
        unsafe { *(&self.padded_enum as *const PRSize as *const PRSockOption) }
    }
    pub fn as_ptr(&self) -> *const PRSocketOptionData {
        self as *const Self as *const PRSocketOptionData
    }
    pub fn as_mut_ptr(&mut self) -> *mut PRSocketOptionData {
        self as *mut Self as *mut PRSocketOptionData
    }
}


pub type PRNetAddrInet = PRNetAddr__bindgen_ty_2;
pub type PRNetAddrInet6 = PRNetAddr__bindgen_ty_3;
