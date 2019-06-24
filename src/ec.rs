use std::mem;
use std::os::raw::{c_uint, c_void};
use std::ptr;
use std::slice;

use nss_sys::{
    ECPointEncoding_ECPoint_Undefined, KeyType_ecKey, PK11_GenerateKeyPairWithOpFlags,
    PORT_ArenaZAlloc, SECITEM_AllocItem, SECITEM_CopyItem, SECItem, SECItemType, SECKEYPrivateKey,
    SECKEYPublicKey, SECKEY_CopyPublicKey, SECKEY_DestroyPrivateKey, SECKEY_DestroyPublicKey,
    SECKEY_ImportDERPublicKey, SECOID_FindOIDByTag, SECOidTag, SECStatus, CKF_DERIVE, CKF_SIGN,
    CKK_EC, CKM_EC_KEY_PAIR_GEN, CK_INVALID_HANDLE, PK11_ATTR_INSENSITIVE, PK11_ATTR_PUBLIC,
    PK11_ATTR_SESSION, SEC_ASN1_OBJECT_ID,
};

use crate::arena::Arena;
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

    pub fn public_key<'a>(&mut self, arena: &'a Arena) -> Result<PublicKey<'a>, ()> {
        // TODO(baloo): CopyPublicKey should move to SECKEY_CopyItem with arena
        let key = unsafe { SECKEY_CopyPublicKey(self.public) };

        if !key.is_null() {
            Ok(PublicKey { arena, key })
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

pub struct AffineCoords {
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

// TOOD(baloo):
pub struct PublicKey<'a> {
    arena: &'a Arena,
    pub(crate) key: *mut SECKEYPublicKey,
}

impl<'a> PublicKey<'a> {
    pub fn import(arena: &'a Arena, curve: Curve, der: &[u8]) -> Result<Self, ()> {
        unsafe {
            let arena_ptr = arena.as_ptr();

            let key = PORT_ArenaZAlloc(arena_ptr, mem::size_of::<SECKEYPublicKey>())
                as *mut SECKEYPublicKey;

            let key = if !key.is_null() {
                Self { arena, key }
            } else {
                return Err(());
            };

            (*key.key).arena = arena_ptr;
            (*key.key).keyType = KeyType_ecKey;

            let mut params = curve.to_params()?;
            let key_curve_params = SECITEM_AllocItem(
                arena_ptr,
                &mut (*key.key).u.ec.DEREncodedParams,
                params.len() as c_uint,
            );
            if key_curve_params.is_null() {
                return Err(());
            }

            let mut curve_params = SECItem {
                type_: SECItemType::siBuffer,
                data: params.as_mut().as_mut_ptr() as *mut u8,
                len: params.len() as c_uint,
            };

            let status = SECITEM_CopyItem(arena_ptr, key_curve_params, &mut curve_params);

            if status != SECStatus::SECSuccess {
                // key_curve_params is to be droped by key drop, no need to drop it manually here
                return Err(());
            }

            (*key.key).u.ec.encoding = ECPointEncoding_ECPoint_Undefined;

            let mut der_owned = Vec::from(der);
            let ecPoint = SECItem {
                type_: SECItemType::siBuffer,
                data: (&mut der_owned[..]).as_mut_ptr(),
                len: der_owned.len() as c_uint,
            };

            let status = SECITEM_CopyItem(arena_ptr, &mut (*key.key).u.ec.publicValue, &ecPoint);

            if status != SECStatus::SECSuccess {
                // key_curve_params is to be droped by key drop, no need to drop it manually here
                return Err(());
            }

            (*key.key).pkcs11Slot = ptr::null_mut();
            (*key.key).pkcs11ID = CK_INVALID_HANDLE;

            Ok(key)
        }
    }

    pub fn import_affine(arena: &'a Arena, curve: Curve, x: &[u8], y: &[u8]) -> Result<Self, Error> {
        if x.len() != y.len() {
            return Err(Error::InvalidParameters);
        }
        let mut der = Vec::with_capacity(1 + x.len() + y.len());
        der.push(0x04);
        der.extend_from_slice(x);
        der.extend_from_slice(y);

        Self::import(arena, curve, der.as_ref())
    }

    pub fn affine_coordinates(&self) -> AffineCoords {
        let ref public = unsafe { (*self.key).u.ec.publicValue };
        if public.data.is_null() {
            panic!("public key should not be null-ptr");
        }

        let data = unsafe { slice::from_raw_parts(public.data, public.len as usize) };

        assert!(data[0] == 0x04);

        let len = (data.len() - 1) / 2;
        let x = Vec::from(&data[1..len + 1]);
        let y = Vec::from(&data[len + 1..]);

        AffineCoords { x, y }
    }
}

impl<'a> Drop for PublicKey<'a> {
    fn drop(&mut self) {
        unsafe {
            SECKEY_DestroyPublicKey(self.key);
        }
    }
}
