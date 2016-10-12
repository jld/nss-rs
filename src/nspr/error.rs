/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use libc::c_char;
use nss_sys::nspr as ffi;
use std::error;
use std::ffi::CStr;
use std::fmt;
use std::io;
use std::result;

pub use ErrorCode;

unsafe fn to_cstr_opt<'a>(ptr: *const c_char) -> Option<&'a CStr> {
    if ptr.is_null() {
        None
    } else {
        Some(CStr::from_ptr(ptr))
    }
}

impl ErrorCode {
    pub fn last() -> Self {
        ErrorCode(unsafe { ffi::PR_GetError() })
    }
    pub fn to_name(self) -> Option<&'static CStr> {
        unsafe {
            to_cstr_opt(ffi::PR_ErrorToName(self.0))
        }
    }
    pub fn to_descr(self) -> Option<&'static CStr> {
        unsafe {
            to_cstr_opt(ffi::PR_ErrorToString(self.0, ffi::PR_LANGUAGE_I_DEFAULT))
        }
    }
}

macro_rules! nspr_errors {{ $($name:ident,)* } => {
    $(pub const $name: ErrorCode = ErrorCode(ffi::$name);)*
}}

impl fmt::Debug for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.to_name() {
            Some(cs) => write!(f, "{}", cs.to_str().unwrap()),
            None => write!(f, "ErrorCode({})", self.0),
        }
    }
}
impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // FIXME: should this use the ToString value instead / as well?
        fmt::Debug::fmt(self, f)
    }
}
impl error::Error for ErrorCode {
    fn description(&self) -> &str {
        match self.to_descr() {
            Some(cs) => cs.to_str().unwrap(),
            None => "Unknown error"
        }
    }
    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

macro_rules! error_kinds {
    { $($ek_name:ident = $pr_name:ident $(| $pr_alias:ident)*),* } => {
        impl ErrorCode {
            // FIXME: should this be Into, or is it too lossy?
            pub fn kind(&self) -> io::ErrorKind {
                match self.0 {
                    $(ffi::$pr_name => io::ErrorKind::$ek_name
                      $(, ffi::$pr_alias => io::ErrorKind::$ek_name)*),*,
                    _ => io::ErrorKind::Other,
                }
            }
        }
        impl From<io::ErrorKind> for ErrorCode {
            fn from(ek: io::ErrorKind) -> Self {
                match ek {
                    $(io::ErrorKind::$ek_name => $pr_name),*,
                    _ => PR_IO_ERROR,
                }
            }
        }
    }
}


#[derive(Clone, Copy, Debug)]
pub struct Error {
    pub nspr_error: ErrorCode,
    pub os_error: i32,
}
impl Error {
    pub fn last() -> Self {
        Error {
            nspr_error: ErrorCode::last(),
            os_error: unsafe { ffi::PR_GetOSError() },
        }
    }
    pub fn set(self) {
        unsafe {
            ffi::PR_SetError(self.nspr_error.0, self.os_error);
        }
    }
}
impl From<ErrorCode> for Error {
    fn from(err: ErrorCode) -> Self {
        Error { nspr_error: err, os_error: 0 }
    }
}
// Are From/Into really right for lossy conversions like these?
impl Into<io::Error> for Error {
    fn into(self) -> io::Error {
        if self.os_error != 0 {
            io::Error::from_raw_os_error(self.os_error)
        } else {
            io::Error::new(self.nspr_error.kind(),
                           Box::new(self.nspr_error))
        }
    }
}
impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error {
            nspr_error: err.kind().into(),
            os_error: err.raw_os_error().unwrap_or(0),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

nspr_errors! {
    PR_OUT_OF_MEMORY_ERROR,
    PR_BAD_DESCRIPTOR_ERROR,
    PR_WOULD_BLOCK_ERROR,
    PR_ACCESS_FAULT_ERROR,
    PR_INVALID_METHOD_ERROR,
    PR_ILLEGAL_ACCESS_ERROR,
    PR_UNKNOWN_ERROR,
    PR_PENDING_INTERRUPT_ERROR,
    PR_NOT_IMPLEMENTED_ERROR,
    PR_IO_ERROR,
    PR_IO_TIMEOUT_ERROR,
    PR_IO_PENDING_ERROR,
    PR_DIRECTORY_OPEN_ERROR,
    PR_INVALID_ARGUMENT_ERROR,
    PR_ADDRESS_NOT_AVAILABLE_ERROR,
    PR_ADDRESS_NOT_SUPPORTED_ERROR,
    PR_IS_CONNECTED_ERROR,
    PR_BAD_ADDRESS_ERROR,
    PR_ADDRESS_IN_USE_ERROR,
    PR_CONNECT_REFUSED_ERROR,
    PR_NETWORK_UNREACHABLE_ERROR,
    PR_CONNECT_TIMEOUT_ERROR,
    PR_NOT_CONNECTED_ERROR,
    PR_LOAD_LIBRARY_ERROR,
    PR_UNLOAD_LIBRARY_ERROR,
    PR_FIND_SYMBOL_ERROR,
    PR_INSUFFICIENT_RESOURCES_ERROR,
    PR_DIRECTORY_LOOKUP_ERROR,
    PR_TPD_RANGE_ERROR,
    PR_PROC_DESC_TABLE_FULL_ERROR,
    PR_SYS_DESC_TABLE_FULL_ERROR,
    PR_NOT_SOCKET_ERROR,
    PR_NOT_TCP_SOCKET_ERROR,
    PR_SOCKET_ADDRESS_IS_BOUND_ERROR,
    PR_NO_ACCESS_RIGHTS_ERROR,
    PR_OPERATION_NOT_SUPPORTED_ERROR,
    PR_PROTOCOL_NOT_SUPPORTED_ERROR,
    PR_REMOTE_FILE_ERROR,
    PR_BUFFER_OVERFLOW_ERROR,
    PR_CONNECT_RESET_ERROR,
    PR_RANGE_ERROR,
    PR_DEADLOCK_ERROR,
    PR_FILE_IS_LOCKED_ERROR,
    PR_FILE_TOO_BIG_ERROR,
    PR_NO_DEVICE_SPACE_ERROR,
    PR_PIPE_ERROR,
    PR_NO_SEEK_DEVICE_ERROR,
    PR_IS_DIRECTORY_ERROR,
    PR_LOOP_ERROR,
    PR_NAME_TOO_LONG_ERROR,
    PR_FILE_NOT_FOUND_ERROR,
    PR_NOT_DIRECTORY_ERROR,
    PR_READ_ONLY_FILESYSTEM_ERROR,
    PR_DIRECTORY_NOT_EMPTY_ERROR,
    PR_FILESYSTEM_MOUNTED_ERROR,
    PR_NOT_SAME_DEVICE_ERROR,
    PR_DIRECTORY_CORRUPTED_ERROR,
    PR_FILE_EXISTS_ERROR,
    PR_MAX_DIRECTORY_ENTRIES_ERROR,
    PR_INVALID_DEVICE_STATE_ERROR,
    PR_DEVICE_IS_LOCKED_ERROR,
    PR_NO_MORE_FILES_ERROR,
    PR_END_OF_FILE_ERROR,
    PR_FILE_SEEK_ERROR,
    PR_FILE_IS_BUSY_ERROR,
    PR_OPERATION_ABORTED_ERROR,
    PR_IN_PROGRESS_ERROR,
    PR_ALREADY_INITIATED_ERROR,
    PR_GROUP_EMPTY_ERROR,
    PR_INVALID_STATE_ERROR,
    PR_NETWORK_DOWN_ERROR,
    PR_SOCKET_SHUTDOWN_ERROR,
    PR_CONNECT_ABORTED_ERROR,
    PR_HOST_UNREACHABLE_ERROR,
    PR_LIBRARY_NOT_LOADED_ERROR,
    PR_CALL_ONCE_ERROR,
}

error_kinds! {
    // Based on decode_error_kind in libstd and _MD_unix_map_default_error in NSPR.
    NotFound          = PR_FILE_NOT_FOUND_ERROR,
    PermissionDenied  = PR_NO_ACCESS_RIGHTS_ERROR | PR_READ_ONLY_FILESYSTEM_ERROR
        | PR_FILE_IS_LOCKED_ERROR | PR_IS_DIRECTORY_ERROR,
    ConnectionRefused = PR_CONNECT_REFUSED_ERROR,
    ConnectionReset   = PR_CONNECT_RESET_ERROR,
    ConnectionAborted = PR_CONNECT_ABORTED_ERROR,
    NotConnected      = PR_NOT_CONNECTED_ERROR,
    AddrInUse         = PR_ADDRESS_IN_USE_ERROR,
    AddrNotAvailable  = PR_ADDRESS_NOT_AVAILABLE_ERROR | PR_BAD_ADDRESS_ERROR,
    BrokenPipe        = PR_SOCKET_SHUTDOWN_ERROR | PR_PIPE_ERROR,
    AlreadyExists     = PR_FILE_EXISTS_ERROR | PR_DIRECTORY_NOT_EMPTY_ERROR,
    WouldBlock        = PR_WOULD_BLOCK_ERROR,
    InvalidInput      = PR_INVALID_ARGUMENT_ERROR | PR_INVALID_METHOD_ERROR
        | PR_BUFFER_OVERFLOW_ERROR | PR_SOCKET_ADDRESS_IS_BOUND_ERROR | PR_BAD_DESCRIPTOR_ERROR,
    TimedOut          = PR_IO_TIMEOUT_ERROR | PR_CONNECT_TIMEOUT_ERROR | PR_REMOTE_FILE_ERROR,
    Interrupted       = PR_PENDING_INTERRUPT_ERROR,
    UnexpectedEof     = PR_END_OF_FILE_ERROR | PR_NO_MORE_FILES_ERROR
}
