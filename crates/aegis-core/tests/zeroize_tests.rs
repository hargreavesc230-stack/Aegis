use aegis_core::crypto::public_key::generate_keypair;
use zeroize::Zeroize;

#[test]
fn private_key_zeroize_clears_bytes() {
    let (mut private_key, _) = generate_keypair().expect("keypair");
    private_key.zeroize();
    assert!(private_key.iter().all(|byte| *byte == 0));
}
