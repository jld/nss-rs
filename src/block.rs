use std::os::raw::c_uint;
use std::ffi::c_void;
use std::mem;
use std::ptr;

use nss_sys::{
    CKM_AES_CBC, CKR_OK, CK_MECHANISM, CK_MECHANISM_TYPE, CK_OBJECT_HANDLE, CK_ULONG,
    CK_AES_CBC_ENCRYPT_DATA_PARAMS, PK11SymKey, SECStatus, PK11_Encrypt, PK11_Decrypt,
};

pub enum Mode {
    AesCbc,
}

impl Mode {
    fn to_ckm(&self) -> CK_MECHANISM_TYPE {
        match *self {
            Mode::AesCbc => CKM_AES_CBC,
        }
    }

    fn pad_size(&self) -> usize {
        match *self {
            // No pad
            Mode::AesCbc => 0,
        }
    }
}

#[derive(Clone)]
pub enum IV {
    NULL,
}

impl IV {
    fn data(&self) -> [u8; 16] {
        [0u8; 16]
    }
}

pub trait KeyProvider {
    fn key(&self) -> *mut PK11SymKey;
}

pub fn encrypt<T: KeyProvider>(key: &T, mode: Mode, iv: &IV, data: &mut [u8]) -> Result<Vec<u8>, ()> {
    let symkey = key.key();
    let mech = mode.to_ckm();
    let mut param = CK_AES_CBC_ENCRYPT_DATA_PARAMS {
        iv: iv.data(),
        pData: data.as_mut_ptr(),
        length: data.len() as CK_ULONG,
    };

    let mut out: Vec<u8> = Vec::with_capacity(data.len() + mode.pad_size());
    out.resize(data.len() + mode.pad_size(), 0);

    let mut outlen = 0;

    let status = unsafe {
        PK11_Encrypt(
            symkey,
            mech,
            mem::transmute(&mut param),
            out.as_mut_slice().as_mut_ptr(),
            &mut outlen,
            out.len() as c_uint,
            data.as_ptr(),
            data.len() as c_uint
        )
    };

    let out = if status == SECStatus::SECSuccess {
        out.truncate(outlen as usize);
        Ok(out)
    } else {
        Err(())
    };

    // Ensure we keep the key alive long enough
    drop(key);

    out
}

pub fn decrypt<T: KeyProvider>(key: &T, mode: Mode, iv: &IV, data: &mut [u8]) -> Result<Vec<u8>, ()> {
    let symkey = key.key();
    let mech = mode.to_ckm();
    let mut param = CK_AES_CBC_ENCRYPT_DATA_PARAMS {
        iv: iv.data(),
        pData: data.as_mut_ptr(),
        length: data.len() as CK_ULONG,
    };

    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    out.resize(data.len(), 0);

    let mut outlen = 0;


    let status = unsafe {
        PK11_Decrypt(
            symkey,
            mech,
            mem::transmute(&mut param),
            out.as_mut_slice().as_mut_ptr(),
            &mut outlen,
            out.len() as c_uint,
            data.as_ptr(),
            data.len() as c_uint
        )
    };

    let out = if status == SECStatus::SECSuccess {
        out.truncate(outlen as usize);
        Ok(out)
    } else {
        Err(())
    };

    // Ensure we keep the key alive long enough
    drop(key);

    out
}
