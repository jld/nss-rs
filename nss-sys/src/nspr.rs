use libc::{c_char, c_int, c_uint, c_void, size_t};

pub type PRIntn = c_int;
pub type PRUintn = c_uint;
pub type PRInt16 = i16;
pub type PRUint16 = u16;
pub type PRInt32 = i32;
pub type PRUint32 = u32;
pub type PRInt64 = i64;
pub type PRUint64 = u64;
pub type PROffset32 = PRInt32;
pub type PROffset64 = PRInt64;

pub type PRBool = PRIntn;
pub const PR_TRUE: PRBool = 1;
pub const PR_FALSE: PRBool = 0;
pub type PRPackedBool = u8;

pub type PRSize = size_t;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum PRStatus {
    PR_FAILURE = -1,
    PR_SUCCESS = 0,
}
pub use self::PRStatus::*;

pub type PRErrorCode = PRInt32;

pub const PR_OUT_OF_MEMORY_ERROR: PRErrorCode = -6000;
pub const PR_BAD_DESCRIPTOR_ERROR: PRErrorCode = -5999;
pub const PR_WOULD_BLOCK_ERROR: PRErrorCode = -5998;
pub const PR_ACCESS_FAULT_ERROR: PRErrorCode = -5997;
pub const PR_INVALID_METHOD_ERROR: PRErrorCode = -5996;
pub const PR_ILLEGAL_ACCESS_ERROR: PRErrorCode = -5995;
pub const PR_UNKNOWN_ERROR: PRErrorCode = -5994;
pub const PR_PENDING_INTERRUPT_ERROR: PRErrorCode = -5993;
pub const PR_NOT_IMPLEMENTED_ERROR: PRErrorCode = -5992;
pub const PR_IO_ERROR: PRErrorCode = -5991;
pub const PR_IO_TIMEOUT_ERROR: PRErrorCode = -5990;
pub const PR_IO_PENDING_ERROR: PRErrorCode = -5989;
pub const PR_DIRECTORY_OPEN_ERROR: PRErrorCode = -5988;
pub const PR_INVALID_ARGUMENT_ERROR: PRErrorCode = -5987;
pub const PR_ADDRESS_NOT_AVAILABLE_ERROR: PRErrorCode = -5986;
pub const PR_ADDRESS_NOT_SUPPORTED_ERROR: PRErrorCode = -5985;
pub const PR_IS_CONNECTED_ERROR: PRErrorCode = -5984;
pub const PR_BAD_ADDRESS_ERROR: PRErrorCode = -5983;
pub const PR_ADDRESS_IN_USE_ERROR: PRErrorCode = -5982;
pub const PR_CONNECT_REFUSED_ERROR: PRErrorCode = -5981;
pub const PR_NETWORK_UNREACHABLE_ERROR: PRErrorCode = -5980;
pub const PR_CONNECT_TIMEOUT_ERROR: PRErrorCode = -5979;
pub const PR_NOT_CONNECTED_ERROR: PRErrorCode = -5978;
pub const PR_LOAD_LIBRARY_ERROR: PRErrorCode = -5977;
pub const PR_UNLOAD_LIBRARY_ERROR: PRErrorCode = -5976;
pub const PR_FIND_SYMBOL_ERROR: PRErrorCode = -5975;
pub const PR_INSUFFICIENT_RESOURCES_ERROR: PRErrorCode = -5974;
pub const PR_DIRECTORY_LOOKUP_ERROR: PRErrorCode = -5973;
pub const PR_TPD_RANGE_ERROR: PRErrorCode = -5972;
pub const PR_PROC_DESC_TABLE_FULL_ERROR: PRErrorCode = -5971;
pub const PR_SYS_DESC_TABLE_FULL_ERROR: PRErrorCode = -5970;
pub const PR_NOT_SOCKET_ERROR: PRErrorCode = -5969;
pub const PR_NOT_TCP_SOCKET_ERROR: PRErrorCode = -5968;
pub const PR_SOCKET_ADDRESS_IS_BOUND_ERROR: PRErrorCode = -5967;
pub const PR_NO_ACCESS_RIGHTS_ERROR: PRErrorCode = -5966;
pub const PR_OPERATION_NOT_SUPPORTED_ERROR: PRErrorCode = -5965;
pub const PR_PROTOCOL_NOT_SUPPORTED_ERROR: PRErrorCode = -5964;
pub const PR_REMOTE_FILE_ERROR: PRErrorCode = -5963;
pub const PR_BUFFER_OVERFLOW_ERROR: PRErrorCode = -5962;
pub const PR_CONNECT_RESET_ERROR: PRErrorCode = -5961;
pub const PR_RANGE_ERROR: PRErrorCode = -5960;
pub const PR_DEADLOCK_ERROR: PRErrorCode = -5959;
pub const PR_FILE_IS_LOCKED_ERROR: PRErrorCode = -5958;
pub const PR_FILE_TOO_BIG_ERROR: PRErrorCode = -5957;
pub const PR_NO_DEVICE_SPACE_ERROR: PRErrorCode = -5956;
pub const PR_PIPE_ERROR: PRErrorCode = -5955;
pub const PR_NO_SEEK_DEVICE_ERROR: PRErrorCode = -5954;
pub const PR_IS_DIRECTORY_ERROR: PRErrorCode = -5953;
pub const PR_LOOP_ERROR: PRErrorCode = -5952;
pub const PR_NAME_TOO_LONG_ERROR: PRErrorCode = -5951;
pub const PR_FILE_NOT_FOUND_ERROR: PRErrorCode = -5950;
pub const PR_NOT_DIRECTORY_ERROR: PRErrorCode = -5949;
pub const PR_READ_ONLY_FILESYSTEM_ERROR: PRErrorCode = -5948;
pub const PR_DIRECTORY_NOT_EMPTY_ERROR: PRErrorCode = -5947;
pub const PR_FILESYSTEM_MOUNTED_ERROR: PRErrorCode = -5946;
pub const PR_NOT_SAME_DEVICE_ERROR: PRErrorCode = -5945;
pub const PR_DIRECTORY_CORRUPTED_ERROR: PRErrorCode = -5944;
pub const PR_FILE_EXISTS_ERROR: PRErrorCode = -5943;
pub const PR_MAX_DIRECTORY_ENTRIES_ERROR: PRErrorCode = -5942;
pub const PR_INVALID_DEVICE_STATE_ERROR: PRErrorCode = -5941;
pub const PR_DEVICE_IS_LOCKED_ERROR: PRErrorCode = -5940;
pub const PR_NO_MORE_FILES_ERROR: PRErrorCode = -5939;
pub const PR_END_OF_FILE_ERROR: PRErrorCode = -5938;
pub const PR_FILE_SEEK_ERROR: PRErrorCode = -5937;
pub const PR_FILE_IS_BUSY_ERROR: PRErrorCode = -5936;
pub const PR_OPERATION_ABORTED_ERROR: PRErrorCode = -5935;
pub const PR_IN_PROGRESS_ERROR: PRErrorCode = -5934;
pub const PR_ALREADY_INITIATED_ERROR: PRErrorCode = -5933;
pub const PR_GROUP_EMPTY_ERROR: PRErrorCode = -5932;
pub const PR_INVALID_STATE_ERROR: PRErrorCode = -5931;
pub const PR_NETWORK_DOWN_ERROR: PRErrorCode = -5930;
pub const PR_SOCKET_SHUTDOWN_ERROR: PRErrorCode = -5929;
pub const PR_CONNECT_ABORTED_ERROR: PRErrorCode = -5928;
pub const PR_HOST_UNREACHABLE_ERROR: PRErrorCode = -5927;
pub const PR_LIBRARY_NOT_LOADED_ERROR: PRErrorCode = -5926;
pub const PR_CALL_ONCE_ERROR: PRErrorCode = -5925;
pub const PR_MAX_ERROR: PRErrorCode = -5924;

#[derive(Debug)]
#[repr(C)]
pub struct PRFileDesc {
    pub methods: *const PRIOMethods,
    pub secret: *mut PRFilePrivate,
    pub lower: *mut PRFileDesc,
    pub higher: *mut PRFileDesc,
    pub dtor: Option<unsafe extern "C" fn(*mut PRFileDesc)>,
    pub identity: PRDescIdentity,
}

// PRFilePrivate is an actual struct used by the core PRFileDesc
// backends, but the `secret` can be anything pointer-sized as long as
// all the methods agree on what it means.  In particular, NSS itself
// does this in `ssl_PushIOLayer`.
pub enum PRFilePrivate {}
pub type PRDescIdentity = PRIntn;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PRIOMethods {
    pub file_type: PRDescType,
    pub close: PRCloseFN,
    pub read: PRReadFN,
    pub write: PRWriteFN,
    pub available: PRAvailableFN,
    pub available64: PRAvailable64FN,
    pub fsync: PRFsyncFN,
    pub seek: PRSeekFN,
    pub seek64: PRSeek64FN,
    pub fileInfo: PRFileInfoFN,
    pub fileInfo64: PRFileInfo64FN,
    pub writev: PRWritevFN,
    pub connect: PRConnectFN,
    pub accept: PRAcceptFN,
    pub bind: PRBindFN,
    pub listen: PRListenFN,
    pub shutdown: PRShutdownFN,
    pub recv: PRRecvFN,
    pub send: PRSendFN,
    pub recvfrom: PRRecvfromFN,
    pub sendto: PRSendtoFN,
    pub poll: PRPollFN,
    pub acceptread: PRAcceptreadFN,
    pub transmitfile: PRTransmitfileFN,
    pub getsockname: PRGetsocknameFN,
    pub getpeername: PRGetpeernameFN,
    pub reserved_fn_6: PRReservedFN,
    pub reserved_fn_5: PRReservedFN,
    pub getsocketoption: PRGetsocketoptionFN,
    pub setsocketoption: PRSetsocketoptionFN,
    pub sendfile: PRSendfileFN,
    pub connectcontinue: PRConnectcontinueFN,
    pub reserved_fn_3: PRReservedFN,
    pub reserved_fn_2: PRReservedFN,
    pub reserved_fn_1: PRReservedFN,
    pub reserved_fn_0: PRReservedFN,
}

// NSPR doesn't treat these as nullable, but NSS sometimes does:
pub type PRCloseFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc)
                                -> PRStatus>;
pub type PRReadFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                buf: *mut c_void,
                                amount: PRInt32)
                                -> PRInt32>;
pub type PRWriteFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                buf: *const c_void,
                                amount: PRInt32)
                                -> PRInt32>;
pub type PRAvailableFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc)
                                -> PRInt32>;
pub type PRAvailable64FN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc)
                                -> PRInt64>;
pub type PRFsyncFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc)
                                -> PRStatus>;
pub type PRSeekFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                offset: PROffset32,
                                how: PRSeekWhence)
                                -> PROffset32>;
pub type PRSeek64FN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                offset: PROffset64,
                                how: PRSeekWhence)
                                -> PROffset64>;
pub type PRFileInfoFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                info: *mut PRFileInfo)
                                -> PRStatus>;
pub type PRFileInfo64FN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                info: *mut PRFileInfo64)
                                -> PRStatus>;
pub type PRWritevFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                iov: *const PRIOVec,
                                iov_size: PRInt32,
                                timeout: PRIntervalTime)
                                -> PRInt32>;
pub type PRConnectFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                addr: *const PRNetAddr,
                                timeout: PRIntervalTime)
                                -> PRStatus>;
pub type PRAcceptFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                addr: *mut PRNetAddr,
                                timeout: PRIntervalTime)
                                -> *mut PRFileDesc>;
pub type PRBindFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                addr: *const PRNetAddr)
                                -> PRStatus>;
pub type PRListenFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                backlog: PRIntn)
                                -> PRStatus>;
pub type PRShutdownFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                how: PRIntn)
                                -> PRStatus>;
pub type PRRecvFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                buf: *mut c_void,
                                amount: PRInt32,
                                flags: PRIntn,
                                timeout: PRIntervalTime)
                                -> PRInt32>;
pub type PRSendFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                buf: *const c_void,
                                amount: PRInt32,
                                flags: PRIntn,
                                timeout: PRIntervalTime)
                                -> PRInt32>;
pub type PRRecvfromFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                buf: *mut c_void,
                                amount: PRInt32,
                                flags: PRIntn,
                                addr: *mut PRNetAddr,
                                timeout: PRIntervalTime)
                                -> PRInt32>;
pub type PRSendtoFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                buf: *const c_void,
                                amount: PRInt32,
                                flags: PRIntn,
                                addr: *const PRNetAddr,
                                timeout: PRIntervalTime)
                                -> PRInt32>;
pub type PRPollFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                in_flags: PRInt16,
                                out_flags: *mut PRInt16)
                                -> PRInt16>;
pub type PRAcceptreadFN =
    Option<unsafe extern "C" fn(sd: *mut PRFileDesc,
                                nd: *mut *mut PRFileDesc,
                                raddr: *mut *mut PRNetAddr,
                                buf: *mut c_void,
                                amount: PRInt32,
                                t: PRIntervalTime)
                                -> PRInt32>;
pub type PRTransmitfileFN =
    Option<unsafe extern "C" fn(sd: *mut PRFileDesc,
                                fd: *mut PRFileDesc,
                                headers: *const c_void,
                                hlen: PRInt32,
                                flags: PRTransmitFileFlags,
                                t: PRIntervalTime)
                                -> PRInt32>;
pub type PRGetsocknameFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                addr: *mut PRNetAddr)
                                -> PRStatus>;
pub type PRGetpeernameFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                addr: *mut PRNetAddr)
                                -> PRStatus>;
pub type PRGetsocketoptionFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                data: *mut PRSocketOptionData)
                                -> PRStatus>;
pub type PRSetsocketoptionFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                data: *const PRSocketOptionData)
                                -> PRStatus>;
pub type PRSendfileFN =
    Option<unsafe extern "C" fn(networkSocket: *mut PRFileDesc,
                                sendData: *mut PRSendFileData,
                                flags: PRTransmitFileFlags,
                                timeout: PRIntervalTime)
                                -> PRInt32>;
pub type PRConnectcontinueFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc,
                                out_flags: PRInt16)
                                -> PRStatus>;
pub type PRReservedFN =
    Option<unsafe extern "C" fn(fd: *mut PRFileDesc)
                                -> PRIntn>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum PRDescType {
    PR_DESC_FILE = 1,
    PR_DESC_SOCKET_TCP = 2,
    PR_DESC_SOCKET_UDP = 3,
    PR_DESC_LAYERED = 4,
    PR_DESC_PIPE = 5,
}
pub use self::PRDescType::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum PRSeekWhence {
    PR_SEEK_SET = 0,
    PR_SEEK_CUR = 1,
    PR_SEEK_END = 2,
}
pub use self::PRSeekWhence::*;

#[derive(Debug)]
#[repr(C)]
pub struct PRIOVec {
    pub iov_base: *mut c_char,
    pub iov_len: c_int,
}

// This is a PRSockOption "discriminant" followed by a union; it's not
// clear how best to glue it onto Rust so that the alignment padding
// always works.  It would probably work to transmute to PRSockOption
// to get the discriminant, then to `(usize, ActualPayload)` to get the
pub enum PRSocketOptionData { }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum PRSockOption {
    PR_SockOpt_Nonblocking = 0,      // PRBool
    PR_SockOpt_Linger = 1,           // PRLinger
    PR_SockOpt_Reuseaddr = 2,        // PRBool
    PR_SockOpt_Keepalive = 3,        // PRBool
    PR_SockOpt_RecvBufferSize = 4,   // PRSize
    PR_SockOpt_SendBufferSize = 5,   // PRSize
    PR_SockOpt_IpTimeToLive = 6,     // PRUintn
    PR_SockOpt_IpTypeOfService = 7,  // PRUintn
    PR_SockOpt_AddMember = 8,        // PRMcastRequest
    PR_SockOpt_DropMember = 9,       // PRMcastRequest
    PR_SockOpt_McastInterface = 10,  // PRNetAddr
    PR_SockOpt_McastTimeToLive = 11, // PRUintn
    PR_SockOpt_McastLoopback = 12,   // PRBool
    PR_SockOpt_NoDelay = 13,         // PRBool
    PR_SockOpt_MaxSegment = 14,      // PRSize
    PR_SockOpt_Broadcast = 15,       // PRBool
    PR_SockOpt_Reuseport = 16,       // PRBool
    PR_SockOpt_Last = 17,
}
pub use self::PRSockOption::*;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PRLinger {
    pub polarity: PRBool,
    pub linger: PRIntervalTime,
}

pub type PRIntervalTime = PRUint32;
pub type PRTime = PRInt64;

// This is a union-of-structs, which matches the original behavior for
// an enum with `#[repr(u16)]`, but that probably isn't guaranteed the
// way `#[repr(C)]` is, and moreover the discriminants are `AF_*`
// constants rather than sequential uints.  So it's better to just do
// this with transmutes.
//
// Also, this is intended to match the OS's `sockaddr` except that it
// always uses the non-BSD style (family: u16, ...) even if the OS is
// BSD (len: u8, family: u8, ...) and mangles the bits when going
// to/from the OS calls.  I think it's best to just reflect what NSPR
// actually declares and make callers manually copy to/from the `libc`
// types, because that will always work.

pub enum PRNetAddr { }

// These are anonymous structs in the C interface, but I'm giving them
// names here.  Also, I'm assuming the target isn't BeOS or OS/2 (this
// changes some of the array sizes).

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PRNetAddrRaw {
    pub family: PRUint16,
    pub data: [c_char; 14], // 10 on BeOS
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PRNetAddrInet {
    pub family: PRUint16, // == AF_INET == 2
    pub port: PRUint16, // FIXME: are these BE like in the BSD things?
    pub ip: PRUint32,
    pub pad: [c_char; 8], // 4 on BeOS
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PRNetAddrInet6 {
    pub family: PRUint16, // == AF_INET6 == 10
    pub port: PRUint16,
    pub flowinfo: PRUint32,
    pub ip: PRIPv6Addr,
    pub scope_id: PRUint32,
}

#[derive(Copy)]
#[repr(C)]
pub struct PRNetAddrLocal {
    pub family: PRUint16, // == AF_LOCAL = 1
    pub path: [c_char; 104], // 108 on OS/2
}
// Can't derive Clone (or Debug) because 104 > 32.
impl Clone for PRNetAddrLocal {
    fn clone(&self) -> Self { *self }
}

// In C this is a union of [u64; 2], [u32, 4], [u16, 8], and [u8; 16].
// In Rust, use transmute instead.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PRIPv6Addr(pub [PRUint64; 2]);

#[derive(Debug)]
#[repr(C)]
pub struct PRSendFileData {
    pub fd: *mut PRFileDesc,
    pub file_offset: PRUint32,
    pub file_nbytes: PRSize,
    pub header: *const c_void,
    pub hlen: PRInt32,
    pub trailer: *const c_void,
    pub tlen: PRInt32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum PRTransmitFileFlags {
    PR_TRANSMITFILE_KEEP_OPEN = 0,
    PR_TRANSMITFILE_CLOSE_SOCKET = 1,
}
pub use self::PRTransmitFileFlags::*;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PRFileInfo {
    pub type_: PRFileType,
    pub size: PROffset32,
    pub creationTime: PRTime,
    pub modifyTime: PRTime,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PRFileInfo64 {
    pub type_: PRFileType,
    pub size: PROffset64,
    pub creationTime: PRTime,
    pub modifyTime: PRTime,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum PRFileType {
    PR_FILE_FILE = 1,
    PR_FILE_DIRECTORY = 2,
    PR_FILE_OTHER = 3,
}
pub use self::PRFileType::*;


#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum PRThreadType {
    PR_USER_THREAD,
    PR_SYSTEM_THREAD
}
pub use self::PRThreadType::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum PRThreadPriority
{
    PR_PRIORITY_LOW = 0,
    PR_PRIORITY_NORMAL = 1,
    PR_PRIORITY_HIGH = 2,
    PR_PRIORITY_URGENT = 3,
}
pub use self::PRThreadPriority::*;

extern "C" {
    // N.B. None of these arguments are used.
    pub fn PR_Init(_type: PRThreadType,
                   _priority: PRThreadPriority,
                   _maxPTDs: PRUintn);

    pub fn PR_GetError() -> PRErrorCode;
    pub fn PR_GetOSError() -> PRInt32;
    pub fn PR_SetError(code: PRErrorCode, orErr: PRInt32);
    // The "error text" facility seems to be used only by
    // PR_LoadLibrary (and only on BeOS?), so not binding it.

    pub fn PR_Close(fd: *mut PRFileDesc) -> PRStatus;
}
