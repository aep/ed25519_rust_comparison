extern crate sha2;
extern crate ed25519_dalek;
extern crate sodiumoxide;
extern crate bs58;
extern crate libhydrogen_sys;
use std::mem;

fn main() {

    // this is a a high entropy random string
    let secret_key_bytes: [u8; ed25519_dalek::SECRET_KEY_LENGTH] = [
        157, 097, 177, 157, 239, 253, 090, 096,
        186, 132, 074, 244, 146, 236, 044, 196,
        068, 073, 197, 105, 123, 050, 105, 025,
        112, 059, 172, 003, 028, 174, 127, 096, ];
    println!("private key:      {:?}", secret_key_bytes);

    let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();


    // ed25519_dalek
    {
        use ed25519_dalek::{SecretKey, PublicKey, Keypair};
        let secret_key: SecretKey = SecretKey::from_bytes(&secret_key_bytes).unwrap();
        let pk: PublicKey = PublicKey::from_secret::<sha2::Sha512>(&secret_key);
        println!("dalek pub:        {:?}", pk.as_bytes());

        let keypair = Keypair{secret: secret_key, public: pk};
        let signature: ed25519_dalek::Signature = keypair.sign::<sha2::Sha512>(message);
        println!("dalek signature:  {:?}", signature.to_bytes().as_ref());
    }


    // libsodium
    {
        use sodiumoxide::crypto::sign;
        let seed    = sign::ed25519::Seed::from_slice(&secret_key_bytes).unwrap();
        let (sp,sk) = sign::ed25519::keypair_from_seed(&seed);

        println!("sodium priv:      {:?}", sk.0.as_ref());
        println!("sodium pub:       {:?}", sp.0.as_ref());

        let signed_data = sign::sign_detached(message, &sk);
        println!("sodium sig:       {:?}", signed_data.0.as_ref());

    }


    // libhydrogen
    {
        // does not work
        // https://github.com/jedisct1/libhydrogen/issues/21
        let keypair = unsafe {
            let mut keypair_c: libhydrogen_sys::hydro_sign_keypair = mem::uninitialized();
            libhydrogen_sys::hydro_sign_keygen_deterministic(&mut keypair_c, secret_key_bytes.as_ptr());
            keypair_c
        };

        println!("hydrogen priv:    {:?}", keypair.sk.as_ref());
        println!("hydrogen pub:     {:?}", keypair.pk.as_ref());
    }
}
