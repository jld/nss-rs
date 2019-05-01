extern crate nss;

use nss::context::Context;
use nss::slot::Slot;
use nss::ec::{KeyPair, Curve};
use nss::agreement::agree_ephemeral;
use nss::block::{encrypt, decrypt, IV, Mode};

#[test]
fn derive_key() {
    let mut context = Context::new().expect("create nss context");
    let mut slot = Slot::internal(&context).expect("get internal slot");
    let mut key_pair = KeyPair::generate(&mut slot, Curve::NistP256).expect("create private key");
    let mut public_key = key_pair.public_key().expect("public key");
    let session_key = agree_ephemeral(&mut key_pair, &mut public_key).expect("agree ephemeral key");
    println!("session_key = {:?}", session_key);

    //assert_eq!(true, false);
}

#[test]
fn encrypt_decrypt() {
    let mut context = Context::new().expect("create nss context");
    let mut slot = Slot::internal(&context).expect("get internal slot");
    let mut key_pair = KeyPair::generate(&mut slot, Curve::NistP256).expect("create private key");
    let mut public_key = key_pair.public_key().expect("public key");
    let session_key = agree_ephemeral(&mut key_pair, &mut public_key).expect("agree ephemeral key");

    let mut data = [0u8; 37];

    let iv = IV::NULL;
    let mut encrypted = encrypt(&session_key, Mode::AesCbc, &iv, &mut data[..]).expect("encrypt data");
    let out = decrypt(&session_key, Mode::AesCbc, &iv, &mut encrypted[..]).expect("decrypt data");

    assert_eq!(&out[..], &data[..]);
    assert_eq!(true, false);
}

