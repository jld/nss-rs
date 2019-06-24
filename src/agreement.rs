use std::ffi::CString;
use std::fmt;
use std::os::raw::c_int;
use std::ptr;
use std::slice;

use nss_sys::nspr::PR_FALSE;
use nss_sys::{
    PK11SymKey, PK11_ExtractKeyValue, PK11_FreeSymKey, PK11_GetKeyData, PK11_GetKeyLength,
    PK11_GetSymKeyNickname, PK11_PubDeriveWithKDF, SECStatus, CKA_DERIVE, CKD_NULL,
    CKM_ECDH1_DERIVE, CKM_NSS_HKDF_SHA256, CK_MECHANISM_TYPE,
};

use crate::block::{KeyProvider, SymKey};
use crate::ec::{KeyPair, PublicKey};
use crate::error::SECErrorCodes;
use crate::port;
use crate::slot::Slot;

#[derive(Debug, Copy, Clone)]
pub enum Mode {
    ECDH1Derive,
    KdfSha256,
}

impl Mode {
    fn to_ckm(self) -> CK_MECHANISM_TYPE {
        match self {
            Mode::ECDH1Derive => CKM_ECDH1_DERIVE,
            Mode::KdfSha256 => CKM_NSS_HKDF_SHA256,
        }
    }

    fn key_size(self) -> c_int {
        match self {
            Mode::ECDH1Derive => 32,
            Mode::KdfSha256 => 32,
        }
    }
}

pub fn agree_ephemeral<'ctx, 'slot, 'a>(
    my_private_key: &mut KeyPair<'ctx, 'slot>,
    peer_public_key: &mut PublicKey<'a>,
    mode: Mode,
) -> Result<EphemeralKey<'ctx, 'slot>, SECErrorCodes> {
    let new_key = unsafe {
        PK11_PubDeriveWithKDF(
            my_private_key.private,
            peer_public_key.key,
            PR_FALSE,
            ptr::null_mut(),
            ptr::null_mut(),
            CKM_ECDH1_DERIVE, // derive
            mode.to_ckm(),    // target
            CKA_DERIVE,       // operation
            mode.key_size(),  // len
            CKD_NULL,         // kdf
            ptr::null_mut(),  // shared data
            ptr::null_mut(),  // wincx
        )
    };

    if !new_key.is_null() {
        Ok(EphemeralKey {
            _slot: my_private_key.slot,
            key: new_key,
        })
    } else {
        Err(port::get_error())
    }
}

pub struct EphemeralKey<'ctx, 'slot> {
    pub(crate) _slot: &'slot Slot<'ctx>,
    key: *mut PK11SymKey,
}

impl<'ctx, 'slot> EphemeralKey<'ctx, 'slot> {
    fn nickname(&self) -> Result<String, ()> {
        let name = unsafe { PK11_GetSymKeyNickname(self.key) };

        if !name.is_null() {
            let data = unsafe { CString::from_raw(name) };
            // Why don't I need to free that?! (I get a double free if I
            // uncomment)
            // unsafe {
            //     PORT_Free(name as *mut c_void)
            // };
            let name = data.into_string().map_err(|_| ())?;
            Ok(name)
        } else {
            Err(())
        }
    }

    pub fn as_buf(&self) -> Result<Option<Vec<u8>>, ()> {
        let len = unsafe { PK11_GetKeyLength(self.key) };

        if len == 0 {
            return Ok(None);
        }

        let status = unsafe { PK11_ExtractKeyValue(self.key) };

        let key_data = if status == SECStatus::SECSuccess {
            let key = unsafe { PK11_GetKeyData(self.key) };

            if !key.is_null() {
                Ok(key)
            } else {
                Err(())
            }
        } else {
            Err(())
        }?;

        let data = unsafe { slice::from_raw_parts((*key_data).data, len as usize) };

        // PK11_GetKeyData gives us a reference to self.key.data there is no
        // need to free that reference.
        // PORT_Free(key_data);

        let data = Vec::from(data);
        Ok(Some(data))
    }
}

impl<'ctx, 'slot> fmt::Debug for EphemeralKey<'ctx, 'slot> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        eprintln!("foo");
        let nickname = self.nickname().map_err(|_| fmt::Error)?;
        let buf = self.as_buf().map_err(|_| fmt::Error)?;

        write!(f, "EphemeralKey(nick={}, buf={:?})", nickname, buf)
    }
}

impl<'ctx, 'slot> Drop for EphemeralKey<'ctx, 'slot> {
    fn drop(&mut self) {
        unsafe { PK11_FreeSymKey(self.key) };
    }
}

impl<'ctx, 'slot> KeyProvider for EphemeralKey<'ctx, 'slot> {
    fn key(&self) -> SymKey {
        SymKey(self.key)
    }
}
