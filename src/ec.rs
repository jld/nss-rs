use std::os::raw::{c_uint, c_void};
use std::ptr;
use std::slice;

use nss_sys::{
    PK11_GenerateKeyPairWithOpFlags, SECITEM_CopyItem, SECItem, SECItemType, SECKEYECPublicKey,
    SECKEYPrivateKey, SECKEYPublicKey, SECKEYPublicKeyStr__bindgen_ty_1, SECKEY_DestroyPrivateKey,
    SECKEY_DestroyPublicKey, SECOID_FindOIDByTag, SECOidTag, SECStatus, CKF_DERIVE, CKF_SIGN,
    CKM_EC_KEY_PAIR_GEN, PK11_ATTR_INSENSITIVE, PK11_ATTR_PUBLIC, PK11_ATTR_SESSION,
    SEC_ASN1_OBJECT_ID,
};

use crate::slot::Slot;

pub enum Curve {
    NistP256,
    NistP384,
}

impl Curve {
    fn to_secoid(&self) -> SECOidTag {
        match *self {
            Curve::NistP256 => SECOidTag::SEC_OID_ANSIX962_EC_PRIME256V1,
            Curve::NistP384 => SECOidTag::SEC_OID_SECG_EC_SECP384R1,
        }
    }

    fn to_params(&self) -> Result<CurveParams, ()> {
        let secoid = self.to_secoid();
        let oiddata = unsafe { SECOID_FindOIDByTag(secoid) };
        if oiddata.is_null() {
            return Err(());
        }

        let data =
            unsafe { slice::from_raw_parts((*oiddata).oid.data, (*oiddata).oid.len as usize) };
        let mut out: Vec<u8> = Vec::with_capacity(2 + data.len());

        out.push(SEC_ASN1_OBJECT_ID);
        out.push(data.len() as u8);
        out.extend_from_slice(data);

        Ok(CurveParams(out))
    }
}

struct CurveParams(Vec<u8>);

impl CurveParams {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl AsMut<[u8]> for CurveParams {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

pub struct KeyPair<'ctx, 'slot> {
    pub(crate) slot: &'slot Slot<'ctx>,
    pub(crate) private: *mut SECKEYPrivateKey,
    pub(crate) public: *mut SECKEYPublicKey,
}

impl<'ctx, 'slot> KeyPair<'ctx, 'slot> {
    pub fn generate(slot: &'slot mut Slot<'ctx>, curve: Curve) -> Result<KeyPair<'ctx, 'slot>, ()> {
        let mut ec_params = curve.to_params()?;

        let mut sec_item = SECItem {
            type_: SECItemType::siBuffer,
            data: ec_params.as_mut().as_mut_ptr() as *mut u8,
            len: ec_params.len() as c_uint,
        };

        let mut public = ptr::null_mut();

        let private = unsafe {
            PK11_GenerateKeyPairWithOpFlags(
                slot.slot,
                CKM_EC_KEY_PAIR_GEN,
                &mut sec_item as *mut SECItem as *mut c_void,
                &mut public,
                PK11_ATTR_SESSION | PK11_ATTR_INSENSITIVE | PK11_ATTR_PUBLIC,
                CKF_DERIVE,
                CKF_DERIVE | CKF_SIGN,
                ptr::null_mut(), // TODO(baloo): this should come from context (from slot)
            )
        };

        // Ensure we do not drop referenced memory too early
        drop(ec_params);

        if !private.is_null() {
            Ok(KeyPair {
                private,
                public,
                slot,
            })
        } else {
            // TODO(baloo): may be return something a bit more explicit
            Err(())
        }
    }

    pub fn public_key(&mut self) -> Result<PublicKey, ()> {
        let mut public_value = SECItem {
            type_: SECItemType::siBuffer,
            data: ptr::null_mut(),
            len: 0,
        };

        let status = unsafe {
            SECITEM_CopyItem(
                ptr::null_mut(), // One would probably want to specify the arena at some point, but ... let's do that later
                &mut public_value,
                &(*self.public).u.ec.publicValue,
            )
        };

        if status != SECStatus::SECSuccess {
            return Err(());
        }

        let mut der = SECItem {
            type_: SECItemType::siBuffer,
            data: ptr::null_mut(),
            len: 0,
        };

        let status = unsafe {
            SECITEM_CopyItem(
                ptr::null_mut(), // One would probably want to specify the arena at some point, but ... let's do that later
                &mut der,
                &(*self.public).u.ec.DEREncodedParams,
            )
        };

        if status == SECStatus::SECSuccess {
            let new_key = unsafe {
                SECKEYPublicKey {
                    keyType: (*self.public).keyType,
                    pkcs11Slot: ptr::null_mut(),
                    pkcs11ID: 0,
                    arena: ptr::null_mut(),
                    u: SECKEYPublicKeyStr__bindgen_ty_1 {
                        ec: SECKEYECPublicKey {
                            DEREncodedParams: der,
                            size: (*self.public).u.ec.size,
                            publicValue: public_value,
                            encoding: (*self.public).u.ec.encoding,
                        },
                    },
                }
            };

            Ok(PublicKey(new_key))
        } else {
            Err(())
        }
    }
}

impl<'ctx, 'slot> Drop for KeyPair<'ctx, 'slot> {
    fn drop(&mut self) {
        unsafe {
            SECKEY_DestroyPublicKey(self.public);
            SECKEY_DestroyPrivateKey(self.private);
        }
    }
}

pub struct PublicKey(pub(crate) SECKEYPublicKey);

impl Drop for PublicKey {
    fn drop(&mut self) {
        unsafe {
            SECKEY_DestroyPublicKey(&mut self.0);
        }
    }
}
