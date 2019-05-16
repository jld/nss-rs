extern crate nss;

use nss::agreement::agree_ephemeral;
use nss::arena::Arena;
use nss::block::{decrypt, encrypt, Mode, IV};
use nss::context::Context;
use nss::ec::{Curve, KeyPair};
use nss::slot::Slot;

#[test]
fn derive_key() {
    let context = Context::new().expect("create nss context");
    let arena = Arena::new(false).expect("create an arena");
    let mut slot = Slot::internal(&context).expect("get internal slot");
    let mut key_pair = KeyPair::generate(&mut slot, Curve::NistP256).expect("create private key");
    let mut public_key = key_pair.public_key(&arena).expect("public key");
    let mode = Mode::Aes256Cbc;
    let session_key =
        agree_ephemeral(&mut key_pair, &mut public_key, mode).expect("agree ephemeral key");
    println!("session_key = {:?}", session_key);

    //assert_eq!(true, false);
}

#[test]
fn encrypt_decrypt() {
    let context = Context::new().expect("create nss context");
    let arena = Arena::new(false).expect("create an arena");
    let mut slot = Slot::internal(&context).expect("get internal slot");
    let mut key_pair = KeyPair::generate(&mut slot, Curve::NistP256).expect("create private key");
    let mut public_key = key_pair.public_key(&arena).expect("public key");
    let mode = Mode::Aes256Cbc;
    let session_key =
        agree_ephemeral(&mut key_pair, &mut public_key, mode).expect("agree ephemeral key");

    let mut data = [0u8; 64];

    let iv = IV::NULL;
    let mut encrypted = encrypt(&session_key, mode, &iv, &mut data[..]).expect("encrypt data");
    let out = decrypt(&session_key, mode, &iv, &mut encrypted[..]).expect("decrypt data");

    assert_eq!(&out[..], &data[..]);
    //assert_eq!(true, false);
}
