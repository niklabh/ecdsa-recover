mod utils;

use sp_core::{ecdsa, blake2_256};
use sp_io::crypto::secp256k1_ecdsa_recover_compressed;
use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn recover(message: &str, signature: &str) -> String {
    let hash = blake2_256(message.as_bytes());

    let mut signature_slice = [0; 65];
    hex::decode_to_slice(signature, &mut signature_slice).expect("Decoding failed");


    if let Ok(recovered_raw) = secp256k1_ecdsa_recover_compressed(&signature_slice, &hash) {
        let recovered = ecdsa::Public::from_raw(recovered_raw);

        return format!("{:?}", hex::encode(recovered.0));
    } else {
        panic!("recovery failed ...!");
    }
}
