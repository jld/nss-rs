/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)] // for CK_STUFF; could lower if cryptoki becomes a submodule
#![allow(non_snake_case)]

pub mod nspr;

use nspr::*;

include!(concat!(env!("OUT_DIR"), "/nss.rs"));

pub const CK_TRUE: CK_BBOOL = 1;
pub const CK_FALSE: CK_BBOOL = 0;

pub const CK_INVALID_HANDLE: CK_OBJECT_HANDLE = 0;

