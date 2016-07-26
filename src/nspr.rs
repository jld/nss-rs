use nss_sys::nspr as sys;
use std::error;
use std::fmt;
use std::sync::{Once, ONCE_INIT};

pub fn init() {
    // NSPR initialization is done implicitly on the first call to any
    // API, but this "run once" check is thread-unsafe -- NSPR's
    // equivalent of `Once` can't be used because its threading layer
    // isn't initialized yet, and its atomics are polyfilled with
    // thread mutexes on some platforms so they're also off-limits.
    static PR_INIT_ONCE: Once = ONCE_INIT;
    PR_INIT_ONCE.call_once(|| {
        // These argument values haven't been used since before NSPR
        // was released as open source, but fill in something reasonable.
        unsafe {
            sys::PR_Init(sys::PR_SYSTEM_THREAD, sys::PR_PRIORITY_NORMAL, 0);
        }
    });
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ErrorCode(sys::PRErrorCode);

impl ErrorCode {
    pub fn last() -> Self {
        ErrorCode(unsafe { sys::PR_GetError() })
    }
}

macro_rules! nspr_errors {
    { $($name:ident = $desc:expr),* } => {
        $(pub const $name: ErrorCode = ErrorCode(sys::$name);)*
        impl fmt::Debug for ErrorCode {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match self.0 {
                    $(sys::$name => f.write_str(stringify!($name))),*,
                    other => write!(f, "ErrorCode({})", other),
                }
            }
        }
        impl fmt::Display for ErrorCode {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                fmt::Debug::fmt(self, f)
            }
        }
        impl error::Error for ErrorCode {
            fn description(&self) -> &str {
                match self.0 {
                    $(sys::$name => $desc),*,
                    _ => "Unknown error"
                }
            }
            fn cause(&self) -> Option<&error::Error> {
                None
            }
        }
    }
}

nspr_errors! {
    PR_OUT_OF_MEMORY_ERROR =      "Memory allocation attempt failed",
    PR_BAD_DESCRIPTOR_ERROR =     "Invalid file descriptor",
    PR_WOULD_BLOCK_ERROR =        "The operation would have blocked",
    PR_ACCESS_FAULT_ERROR =       "Invalid memory address argument",
    PR_INVALID_METHOD_ERROR =     "Invalid function for file type",
    PR_ILLEGAL_ACCESS_ERROR =     "Invalid memory address argument",
    PR_UNKNOWN_ERROR =            "Some unknown error has occurred",
    PR_PENDING_INTERRUPT_ERROR =  "Operation interrupted by another thread",
    PR_NOT_IMPLEMENTED_ERROR =    "function not implemented",
    PR_IO_ERROR =                 "I/O function error",
    PR_IO_TIMEOUT_ERROR =         "I/O operation timed out",
    PR_IO_PENDING_ERROR =         "I/O operation on busy file descriptor",
    PR_DIRECTORY_OPEN_ERROR =     "The directory could not be opened",
    PR_INVALID_ARGUMENT_ERROR =   "Invalid function argument",
    PR_ADDRESS_NOT_AVAILABLE_ERROR = "Network address not available (in use?)",
    PR_ADDRESS_NOT_SUPPORTED_ERROR = "Network address type not supported",
    PR_IS_CONNECTED_ERROR =       "Already connected",
    PR_BAD_ADDRESS_ERROR =        "Network address is invalid",
    PR_ADDRESS_IN_USE_ERROR =     "Local Network address is in use",
    PR_CONNECT_REFUSED_ERROR =    "Connection refused by peer",
    PR_NETWORK_UNREACHABLE_ERROR = "Network address is presently unreachable",
    PR_CONNECT_TIMEOUT_ERROR =    "Connection attempt timed out",
    PR_NOT_CONNECTED_ERROR =      "Network file descriptor is not connected",
    PR_LOAD_LIBRARY_ERROR =       "Failure to load dynamic library",
    PR_UNLOAD_LIBRARY_ERROR =     "Failure to unload dynamic library",
    PR_FIND_SYMBOL_ERROR =        "Symbol not found in any of the loaded dynamic libraries",
    PR_INSUFFICIENT_RESOURCES_ERROR = "Insufficient system resources",
    PR_DIRECTORY_LOOKUP_ERROR =   "A directory lookup on a network address has failed",
    PR_TPD_RANGE_ERROR =          "Attempt to access a TPD key that is out of range",
    PR_PROC_DESC_TABLE_FULL_ERROR = "Process open FD table is full",
    PR_SYS_DESC_TABLE_FULL_ERROR = "System open FD table is full",
    PR_NOT_SOCKET_ERROR =         "Network operation attempted on non-network file descriptor",
    PR_NOT_TCP_SOCKET_ERROR =     "TCP-specific function attempted on a non-TCP file descriptor",
    PR_SOCKET_ADDRESS_IS_BOUND_ERROR = "TCP file descriptor is already bound",
    PR_NO_ACCESS_RIGHTS_ERROR =   "Access Denied",
    PR_OPERATION_NOT_SUPPORTED_ERROR = "The requested operation is not supported by the platform",
    PR_PROTOCOL_NOT_SUPPORTED_ERROR =
        "The host operating system does not support the protocol requested",
    PR_REMOTE_FILE_ERROR =        "Access to the remote file has been severed",
    PR_BUFFER_OVERFLOW_ERROR =
        "The value requested is too large to be stored in the data buffer provided",
    PR_CONNECT_RESET_ERROR =      "TCP connection reset by peer",
    PR_RANGE_ERROR =              "Unused (range error)",
    PR_DEADLOCK_ERROR =   "The operation would have deadlocked",
    PR_FILE_IS_LOCKED_ERROR =     "The file is already locked",
    PR_FILE_TOO_BIG_ERROR =       "Write would result in file larger than the system allows",
    PR_NO_DEVICE_SPACE_ERROR =    "The device for storing the file is full",
    PR_PIPE_ERROR =               "Unused (pipe error)",
    PR_NO_SEEK_DEVICE_ERROR =     "Unused (device seek error)",
    PR_IS_DIRECTORY_ERROR =       "Cannot perform a normal file operation on a directory",
    PR_LOOP_ERROR =               "Symbolic link loop",
    PR_NAME_TOO_LONG_ERROR =      "File name is too long",
    PR_FILE_NOT_FOUND_ERROR =     "File not found",
    PR_NOT_DIRECTORY_ERROR =      "Cannot perform directory operation on a normal file",
    PR_READ_ONLY_FILESYSTEM_ERROR = "Cannot write to a read-only file system",
    PR_DIRECTORY_NOT_EMPTY_ERROR = "Cannot delete a directory that is not empty",
    PR_FILESYSTEM_MOUNTED_ERROR =
        "Cannot delete or rename a file object while the file system is busy",
    PR_NOT_SAME_DEVICE_ERROR = "Cannot rename a file to a file system on another device",
    PR_DIRECTORY_CORRUPTED_ERROR = "The directory object in the file system is corrupted",
    PR_FILE_EXISTS_ERROR =        "Cannot create or rename a filename that already exists",
    PR_MAX_DIRECTORY_ENTRIES_ERROR = "Directory is full.  No additional filenames may be added",
    PR_INVALID_DEVICE_STATE_ERROR = "The required device was in an invalid state",
    PR_DEVICE_IS_LOCKED_ERROR =   "The device is locked",
    PR_NO_MORE_FILES_ERROR =      "No more entries in the directory",
    PR_END_OF_FILE_ERROR =        "Encountered end of file",
    PR_FILE_SEEK_ERROR =          "Seek error",
    PR_FILE_IS_BUSY_ERROR =       "The file is busy",
    PR_OPERATION_ABORTED_ERROR =  "The I/O operation was aborted",
    PR_IN_PROGRESS_ERROR =
        "Operation is still in progress (probably a non-blocking connect)",
    PR_ALREADY_INITIATED_ERROR =
        "Operation has already been initiated (probably a non-blocking connect)",
    PR_GROUP_EMPTY_ERROR =        "The wait group is empty",
    PR_INVALID_STATE_ERROR =      "Object state improper for request",
    PR_NETWORK_DOWN_ERROR =       "Network is down",
    PR_SOCKET_SHUTDOWN_ERROR =    "Socket shutdown",
    PR_CONNECT_ABORTED_ERROR =    "Connection aborted",
    PR_HOST_UNREACHABLE_ERROR =   "Host is unreachable",
    PR_LIBRARY_NOT_LOADED_ERROR = "The library is not loaded",
    PR_CALL_ONCE_ERROR = "The one-time function was previously called and failed. Its error code is no longer available"
}
