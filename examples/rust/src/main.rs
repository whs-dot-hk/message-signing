use bip39::{Language, Mnemonic};
use cardano_serialization_lib as csl;
use serde_cbor::Value;
use std::collections::BTreeMap;

fn harden(index: u32) -> u32 {
    0x80000000 + index
}

fn derive_stake_key_from_mnemonic(
    mnemonic_phrase: &str,
) -> Result<csl::PrivateKey, Box<dyn std::error::Error>> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_phrase)?;
    let entropy = mnemonic.to_entropy();

    // Use Cardano's proper BIP32 key derivation
    let root_key = csl::Bip32PrivateKey::from_bip39_entropy(&entropy, &[]);

    // Derive the stake key using standard Cardano path: m/1852'/1815'/0'/2/0
    let account_key = root_key
        .derive(harden(1852)) // purpose
        .derive(harden(1815)) // coin_type (ADA)
        .derive(harden(0)); // account

    // Derive stake key: m/1852'/1815'/0'/2/0
    let stake_key = account_key
        .derive(2) // role (2 = staking)
        .derive(0); // index

    Ok(stake_key.to_raw_key())
}

fn get_stake_address(public_key: &csl::PublicKey, network_id: u8) -> String {
    let stake_credential = csl::Credential::from_keyhash(&public_key.hash());

    let reward_address = csl::RewardAddress::new(network_id, &stake_credential);

    reward_address.to_address().to_bech32(None).unwrap()
}

fn main() {
    let mnemonic_phrase = "";

    let stake_sk = derive_stake_key_from_mnemonic(mnemonic_phrase).unwrap();
    let stake_pk = stake_sk.to_public();

    println!("Public key: {}", hex::encode(stake_pk.as_bytes()));

    let network_id = 1;
    let stake_address = get_stake_address(&stake_pk, network_id);
    println!("Cardano stake address (reward address): {stake_address}");

    let message = "";
    println!("Message to sign: {message}");

    // Get the raw address bytes (decode from bech32)
    let address_raw = csl::Address::from_bech32(&stake_address)
        .unwrap()
        .to_bytes();

    // Create protected headers manually to match the expected format
    let mut protected_headers = BTreeMap::new();
    protected_headers.insert(Value::Integer(1), Value::Integer(-8)); // algorithm: EdDSA
    protected_headers.insert(
        Value::Text("address".to_string()),
        Value::Bytes(address_raw),
    );
    let protected_cbor = serde_cbor::to_vec(&Value::Map(protected_headers)).unwrap();

    // Create unprotected headers
    let mut unprotected_headers = BTreeMap::new();
    unprotected_headers.insert(Value::Text("hashed".to_string()), Value::Bool(true));

    // Payload
    let payload = message.as_bytes().to_vec();

    // Create SigStructure for signing
    // SigStructure = [
    //   "Signature1",   // context
    //   protected,      // protected headers
    //   external_aad,   // external AAD (empty)
    //   payload         // payload
    // ]
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected_cbor.clone()),
        Value::Bytes(vec![]), // empty external AAD
        Value::Bytes(payload.clone()),
    ]);

    let to_sign = serde_cbor::to_vec(&sig_structure).unwrap();
    let signature = stake_sk.sign(&to_sign).to_bytes();

    // Create the final COSE Sign1 structure
    // COSE_Sign1 = [
    //   protected,      // protected headers as bytes
    //   unprotected,    // unprotected headers as map
    //   payload,        // payload
    //   signature       // signature
    // ]
    let cose_sign1 = Value::Array(vec![
        Value::Bytes(protected_cbor),
        Value::Map(unprotected_headers),
        Value::Bytes(payload),
        Value::Bytes(signature.to_vec()),
    ]);

    let cose_sign1_bytes = serde_cbor::to_vec(&cose_sign1).unwrap();
    println!("COSE Sign1 format: {}", hex::encode(&cose_sign1_bytes));

    // Verify the signature
    let sig = csl::Ed25519Signature::from_bytes(signature).unwrap();
    let is_valid = stake_pk.verify(&to_sign, &sig);

    println!(
        "Message signature verification: {}",
        if is_valid { "PASSED" } else { "FAILED" }
    );
}
