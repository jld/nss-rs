use std::os::raw::c_int;
use std::mem;

use nss_sys::{
    PORT_GetError,
};

use crate::error;

pub(crate) trait FromCInt {
    fn from_cint(e: c_int) -> Self;
}

impl FromCInt for error::SECErrorCodes {
   fn from_cint(e: c_int) -> Self {
        unsafe { mem::transmute(e) }
    }
}

impl FromCInt for error::SSLErrorCodes {
   fn from_cint(e: c_int) -> Self {
        unsafe { mem::transmute(e) }
    }
}


pub(crate) fn get_error<T: FromCInt>() -> T {
    let e = unsafe {PORT_GetError()};
    T::from_cint(e)
}
