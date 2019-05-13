use std::mem;
use std::os::raw::{c_int, c_uint};

use nss_sys::{
    PK11SymKey, PK11_Decrypt, PK11_Encrypt, SECItem, SECItemType, SECStatus, CKM_AES_CBC,
    CK_AES_CBC_ENCRYPT_DATA_PARAMS, CK_MECHANISM_TYPE, CK_ULONG,
};

use crate::error::SECErrorCodes;
use crate::port;

#[derive(Copy, Clone, Debug)]
pub enum Mode {
    Aes256Cbc,
}

impl Mode {
    pub(crate) fn to_ckm(self) -> CK_MECHANISM_TYPE {
        match self {
            Mode::Aes256Cbc => CKM_AES_CBC,
        }
    }

    fn pad_size(self) -> usize {
        match self {
            // No pad
            Mode::Aes256Cbc => 0,
        }
    }

    pub(crate) fn key_size(self) -> c_int {
        match self {
            Mode::Aes256Cbc => 32,
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

pub struct SymKey(pub(crate) *mut PK11SymKey);

pub trait KeyProvider {
    fn key(&self) -> SymKey;
}

pub fn encrypt<T: KeyProvider>(
    key: &T,
    mode: Mode,
    iv: &IV,
    data: &mut [u8],
) -> Result<Vec<u8>, SECErrorCodes> {
    let symkey = key.key().0;
    let mech = mode.to_ckm();
    let mut aes_param = CK_AES_CBC_ENCRYPT_DATA_PARAMS {
        iv: iv.data(),
        pData: data.as_mut_ptr(),
        length: data.len() as CK_ULONG,
    };

    let mut out: Vec<u8> = Vec::with_capacity(data.len() + mode.pad_size());
    out.resize(data.len() + mode.pad_size(), 0);

    let mut outlen = 0;

    let mut param = SECItem {
        type_: SECItemType::siBuffer,
        data: &mut aes_param as *mut CK_AES_CBC_ENCRYPT_DATA_PARAMS as *mut u8,
        len: mem::size_of_val(&aes_param) as c_uint,
    };

    let status = unsafe {
        PK11_Encrypt(
            symkey,
            mech,
            &mut param as *mut SECItem,
            out.as_mut_slice().as_mut_ptr(),
            &mut outlen,
            out.len() as c_uint,
            data.as_ptr(),
            data.len() as c_uint,
        )
    };

    if status == SECStatus::SECSuccess {
        out.truncate(outlen as usize);
        Ok(out)
    } else {
        Err(port::get_error())
    }
}

pub fn decrypt<T: KeyProvider>(
    key: &T,
    mode: Mode,
    iv: &IV,
    data: &mut [u8],
) -> Result<Vec<u8>, SECErrorCodes> {
    let symkey = key.key().0;
    let mech = mode.to_ckm();
    let mut aes_param = CK_AES_CBC_ENCRYPT_DATA_PARAMS {
        iv: iv.data(),
        pData: data.as_mut_ptr(),
        length: data.len() as CK_ULONG,
    };

    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    out.resize(data.len(), 0);

    let mut outlen = 0;

    let mut param = SECItem {
        type_: SECItemType::siBuffer,
        data: &mut aes_param as *mut CK_AES_CBC_ENCRYPT_DATA_PARAMS as *mut u8,
        len: mem::size_of_val(&aes_param) as c_uint,
    };

    let status = unsafe {
        PK11_Decrypt(
            symkey,
            mech,
            &mut param as *mut SECItem,
            out.as_mut_slice().as_mut_ptr(),
            &mut outlen,
            out.len() as c_uint,
            data.as_ptr(),
            data.len() as c_uint,
        )
    };

    if status == SECStatus::SECSuccess {
        out.truncate(outlen as usize);
        Ok(out)
    } else {
        Err(port::get_error())
    }
}
