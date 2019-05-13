use nss_sys::{PK11SlotInfo, PK11_GetInternalSlot};

use crate::context::Context;

pub struct Slot<'ctx> {
    _context: &'ctx Context,
    pub(crate) slot: *mut PK11SlotInfo,
}

impl<'ctx> Slot<'ctx> {
    pub fn internal(context: &'ctx Context) -> Result<Slot<'ctx>, ()> {
        let slot = unsafe { PK11_GetInternalSlot() };

        if !slot.is_null() {
            Ok(Slot {
                _context: context,
                slot,
            })
        } else {
            Err(())
        }
    }
}
