/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

pub mod error;
pub mod fd;
pub mod net;
pub mod time;

use nss_sys::nspr as ffi;

use std::marker::PhantomData;
use std::sync::{Once, ONCE_INIT};

use GenStatus;
pub use self::fd::File;

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
            ffi::PR_Init(ffi::PR_SYSTEM_THREAD, ffi::PR_PRIORITY_NORMAL, 0);
        }
    });
}

impl From<ffi::PRStatus> for GenStatus<()> {
    fn from(status: ffi::PRStatus) -> Self {
        match status {
            ffi::PR_SUCCESS => GenStatus::Success(()),
            ffi::PR_FAILURE => GenStatus::ErrorFromC,
        }
    }
}

impl From<i32> for GenStatus<usize> {
    fn from(rv: i32) -> Self {
        if rv >= 0 {
            GenStatus::Success(rv as usize)
        } else {
            GenStatus::ErrorFromC
        }
    }
}

pub fn bool_from_nspr(b: ffi::PRBool) -> bool {
    match b {
        ffi::PR_FALSE => false,
        ffi::PR_TRUE => true,
        _ => unreachable!(),
    }
}

pub fn bool_to_nspr(b: bool) -> ffi::PRBool {
    if b {
        ffi::PR_TRUE
    } else {
        ffi::PR_FALSE
    }
}


pub type ListNode = *mut ffi::PRCList;

pub trait Listable {
    unsafe fn from_list_node(node: ListNode) -> Self;
}

#[derive(Clone, Debug)]
pub struct ListIterator<'l, L: Listable + 'l> {
    next: ListNode,
    end: ListNode,
    phantom: PhantomData<&'l [L]>,
}

impl<'l, L: Listable + 'l> ListIterator<'l, L> {
    pub unsafe fn new(list: ListNode) -> Self {
        ListIterator {
            next: (*list).next,
            end: list,
            phantom: PhantomData,
        }
    }
}

impl<'l, L: Listable + 'l> Iterator for ListIterator<'l, L> {
    type Item = L;
    fn next(&mut self) -> Option<L> {
        if self.next == self.end {
            None
        } else {
            unsafe {
                let next = self.next;
                self.next = (*next).next;
                Some(Listable::from_list_node(next))
            }
        }
    }
}

impl<'l, L: Listable + 'l> DoubleEndedIterator for ListIterator<'l, L> {
    fn next_back(&mut self) -> Option<L> {
        if self.next == self.end {
            None
        } else {
            unsafe {
                let prev = (*self.end).prev;
                self.end = prev;
                Some(Listable::from_list_node(prev))
            }
        }
    }
}
