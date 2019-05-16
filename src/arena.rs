use nss_sys::nspr::{PR_FALSE, PR_TRUE};
use nss_sys::{PLArenaPool, PORT_FreeArena, PORT_NewArena, DER_DEFAULT_CHUNKSIZE};

pub struct Arena {
    pool: *mut PLArenaPool,
    sensitive: bool,
}

impl Arena {
    pub fn new(sensitive: bool) -> Result<Self, ()> {
        let pool = unsafe { PORT_NewArena(DER_DEFAULT_CHUNKSIZE) };

        if pool.is_null() {
            Err(())
        } else {
            Ok(Self { sensitive, pool })
        }
    }

    pub(crate) fn as_ptr(&self) -> *mut PLArenaPool {
        self.pool
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        let zeroize = if self.sensitive { PR_TRUE } else { PR_FALSE };

        unsafe {
            //PORT_FreeArena(self.pool, zeroize);
        }
    }
}
