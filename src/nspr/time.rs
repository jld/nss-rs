/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use nss_sys::nspr as ffi;
use std::time::Duration;
use std::u32;

lazy_static! {
    static ref NSPR_TICKS_PER_SEC: u32 = {
        super::init();
        unsafe { ffi::PR_TicksPerSecond() }
    };
}

fn scale_u32(input: u32, in_scale: u32, out_scale: u32) -> u32 {
    debug_assert!(input <= in_scale);
    ((input as u64) * (out_scale as u64) / (in_scale as u64)) as u32
}

pub fn duration_to_nspr(d: Duration) -> ffi::PRIntervalTime {
    let tps = *NSPR_TICKS_PER_SEC;
    let whole = d.as_secs();
    let frac = scale_u32(d.subsec_nanos(), 1_000_000_000, tps);
    let ticks = whole.saturating_mul(tps as u64).saturating_add(frac as u64);
    if ticks <= u32::MAX as u64 {
        ticks as u32
    } else {
        // FIXME: should this really overflow to no timeout, or to highest non-infinite,
        // or return an option/result, or...?
        ffi::PR_INTERVAL_NO_TIMEOUT
    }
}

pub fn duration_opt_to_nspr(d: Option<Duration>) -> ffi::PRIntervalTime {
    d.map_or(ffi::PR_INTERVAL_NO_TIMEOUT, duration_to_nspr)
}

pub fn duration_from_nspr(it: ffi::PRIntervalTime) -> Duration {
    // FIXME should this assert it's not NO_TIMEOUT?
    // Seems wrong given it's the result of overflow above.
    let tps = *NSPR_TICKS_PER_SEC;
    Duration::new((it / tps) as u64, scale_u32(it % tps, tps, 1_000_000_000))
}

pub fn duration_opt_from_nspr(it: ffi::PRIntervalTime) -> Option<Duration> {
    if it == ffi::PR_INTERVAL_NO_TIMEOUT {
        None
    } else {
        Some(duration_from_nspr(it))
    }
}

// FIXME needs unit tests.
