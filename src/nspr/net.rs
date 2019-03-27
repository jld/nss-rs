/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use libc::{c_int, AF_INET, AF_INET6};
use nss_sys::nspr as ffi;
use std::net::{SocketAddr,SocketAddrV4,SocketAddrV6,Ipv4Addr,Ipv6Addr};
use std::mem;
use std::u16;
use nspr::error::Result;
use nspr::fd::File;
use wrap_ffi;

pub struct NetAddrStorage(ffi::PRNetAddr);
impl NetAddrStorage {
    pub fn new() -> Self { unsafe { mem::uninitialized() } }
    pub fn as_ptr(&self) -> *const ffi::PRNetAddr { self as *const NetAddrStorage as *const _ }
    pub fn as_mut_ptr(&mut self) -> *mut ffi::PRNetAddr { self as *mut NetAddrStorage as *mut _ }
}

pub unsafe fn read_net_addr(ptr: *const ffi::PRNetAddr) -> Option<SocketAddr> {
    // This is kind of ridiculous given that they're almost the same structure internally....
    let family = (*ptr).raw.family;
    if family == AF_INET as u16 {
        let port = u16::from_be((*ptr).inet.port);
        let ip: [u8; 4] = mem::transmute((*ptr).inet.ip);
        Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), port)))
    } else if family == AF_INET6 as u16 {
        let port = u16::from_be((*ptr).ipv6.port);
        let mut ip: [u16; 8] = mem::transmute((*ptr).ipv6.ip);
        for seg in ip.iter_mut() {
            *seg = u16::from_be(*seg)
        }
        Some(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(ip[0], ip[1], ip[2], ip[3],
                                                            ip[4], ip[5], ip[6], ip[7]),
                                              port, (*ptr).ipv6.flowinfo, (*ptr).ipv6.scope_id)))
    } else {
        None
    }
}

pub unsafe fn write_net_addr(ptr: *mut ffi::PRNetAddr, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(addr) => {
            *(ptr as *mut _) = ffi::PRNetAddrInet {
                family: AF_INET as u16,
                port: u16::to_be(addr.port()),
                ip: mem::transmute(addr.ip().octets()),
                pad: mem::uninitialized(),
            }
        }
        SocketAddr::V6(addr) => {
            let mut ip = addr.ip().segments();
            for seg in ip.iter_mut() {
                *seg = u16::to_be(*seg)
            }
            *(ptr as *mut _) = ffi::PRNetAddrInet6 {
                family: AF_INET6 as u16,
                port: u16::to_be(addr.port()),
                flowinfo: addr.flowinfo(),
                ip: mem::transmute(ip),
                scope_id: addr.scope_id(),
            }
        }
    }
}

pub fn new_tcp_socket(af: c_int) -> Result<File> {
    super::init();
    wrap_ffi(|| unsafe { File::from_raw_prfd_err(ffi::PR_OpenTCPSocket(af)) })
}

pub fn new_udp_socket(af: c_int) -> Result<File> {
    super::init();
    wrap_ffi(|| unsafe { File::from_raw_prfd_err(ffi::PR_OpenUDPSocket(af)) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nss_sys::nspr as ffi;
    use libc::AF_INET;
    use std::mem;
    use std::net::{SocketAddr,SocketAddrV4,SocketAddrV6,Ipv4Addr,Ipv6Addr};

    #[test]
    fn drop_tcp() {
        let _fd = new_tcp_socket(AF_INET).unwrap();
    }

    #[test]
    fn drop_udp() {
        let _fd = new_udp_socket(AF_INET).unwrap();
    }

    #[test]
    fn v4_addr_rdwr() {
        let mut buf = vec![0u8; mem::size_of::<ffi::PRNetAddrInet>()];
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 128, 129, 130), 443));

        unsafe { write_net_addr(buf.as_mut_ptr() as *mut ffi::PRNetAddr, addr) };
        let got_addr = (unsafe { read_net_addr(buf.as_ptr() as *const ffi::PRNetAddr)}).unwrap();
        assert_eq!(got_addr, addr);
    }

    #[test]
    fn v6_addr_rdwr() {
        let mut buf = vec![0u8; mem::size_of::<ffi::PRNetAddrInet6>()];
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0x405, 0x607,
                                                                  0x809, 0xa0b, 0xc0d, 0xe0f),
                                                    8080, 0x23456, 0x23456789));
        
        unsafe { write_net_addr(buf.as_mut_ptr() as *mut ffi::PRNetAddr, addr) };
        let got_addr = (unsafe { read_net_addr(buf.as_ptr() as *const ffi::PRNetAddr)}).unwrap();
        assert_eq!(got_addr, addr);
    }
    
    // Need better tests that these are actually meaning-preserving, not just inverses.
}
