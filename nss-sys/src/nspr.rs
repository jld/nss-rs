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
    // TODO: the other statuses.
    // Also maybe this should be a typedef and consts.
}
pub use self::PRStatus::*;

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
}
