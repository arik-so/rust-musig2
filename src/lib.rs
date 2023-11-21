#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(warnings)]

//! Experimental crate implementing partial MuSig2 functions. Key tweaking is not supported.

use std::borrow::Borrow;

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256::HashEngine as ShaEngine;
use bitcoin::secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::secp256k1::schnorr::Signature;

use crate::key_preparation::{aggregate_ordered_keys, has_even_y, key_aggregation_coefficient};
pub use crate::key_preparation::aggregate_keys;
pub use crate::nonce_preparation::aggregate_nonces;
use crate::nonce_preparation::calculate_final_nonce;
use crate::types::{AggregateKey, PartialSignature, PublicNonce, SecretNonce, SignerPublicKeys};

pub mod types;
mod key_preparation;
mod nonce_preparation;

/// Create a partial MuSig2 signature.
///
/// Note: This does not include the partial nonce.
pub fn sign<C: bitcoin::secp256k1::Signing + bitcoin::secp256k1::Verification>(secret_key: &SecretKey, secret_nonce: &SecretNonce, aggregate_nonce: &PublicNonce, keys: &SignerPublicKeys, message: &[u8], secp_context: &Secp256k1<C>) -> PartialSignature {
	let ordered_keys = keys.ordered_keys();
	let aggregate_public_key = aggregate_ordered_keys(&ordered_keys, &secp_context);
	let (effective_nonce, nonce_coefficient) = calculate_final_nonce(aggregate_nonce, &aggregate_public_key, message, &secp_context);

	let final_secret_nonce = if has_even_y(&effective_nonce) {
		secret_nonce.clone()
	} else {
		secret_nonce.negate()
	};

	// determine whether the aggregate public key has an even y coordinate
	let final_secret_key = if let Parity::Even = aggregate_public_key.parity {
		secret_key.clone()
	} else {
		secret_key.negate()
	};

	let m = tagged_hash_scalar("BIP0340/challenge", &[
		&effective_nonce.x_only_public_key().0.serialize(),
		&aggregate_public_key.key.serialize(),
		message
	]);

	let a = key_aggregation_coefficient(&ordered_keys, &secret_key.public_key(&secp_context));
	// m*a*d
	let summand_a = final_secret_key.mul_tweak(&m).unwrap().mul_tweak(&a).unwrap();
	// b*k2
	let summand_b = final_secret_nonce.1.mul_tweak(&nonce_coefficient).unwrap();
	// s = m*a*d + k1 + b*k2
	let s = summand_a.add_tweak(&Scalar::from(summand_b)).unwrap().add_tweak(&Scalar::from(final_secret_nonce.0)).unwrap();
	let is_valid = verify_partial_signature(&PartialSignature(s), &secret_nonce.to_public(&secp_context), aggregate_nonce, &secret_key.public_key(&secp_context), keys, message, secp_context);
	assert!(is_valid);
	PartialSignature(s)
}

/// Aggregate partial MuSig2 signatures into the final Schnorr signature
pub fn aggregate_partial_signatures<K: Borrow<PartialSignature>>(partial_signatures: &[K], final_nonce: &PublicKey) -> Signature {
	let mut aggregate_signature = Scalar::ZERO;
	for current_signature in partial_signatures {
		aggregate_signature = Scalar::from(current_signature.borrow().0.add_tweak(&aggregate_signature).unwrap());
	}
	let mut serialized_signature = Vec::with_capacity(64);
	serialized_signature.extend_from_slice(&final_nonce.x_only_public_key().0.serialize());
	serialized_signature.extend_from_slice(&aggregate_signature.to_be_bytes());
	Signature::from_slice(&serialized_signature).unwrap()
}

/// Verify partial MuSig2 signature
pub fn verify_partial_signature<C: bitcoin::secp256k1::Verification + bitcoin::secp256k1::Signing>(partial_signature: &PartialSignature, partial_public_nonce: &PublicNonce, aggregate_public_nonce: &PublicNonce, partial_public_key: &PublicKey, keys: &SignerPublicKeys, message: &[u8], secp_context: &Secp256k1<C>) -> bool {
	let ordered_keys = keys.ordered_keys();
	verify_partial_signature_with_ordered_keys(partial_signature, partial_public_nonce, aggregate_public_nonce, partial_public_key, &ordered_keys, message, secp_context)
}

fn verify_partial_signature_with_ordered_keys<K: Borrow<PublicKey>, C: bitcoin::secp256k1::Verification + bitcoin::secp256k1::Signing>(partial_signature: &PartialSignature, partial_public_nonce: &PublicNonce, aggregate_public_nonce: &PublicNonce, partial_public_key: &PublicKey, ordered_keys: &[K], message: &[u8], secp_context: &Secp256k1<C>) -> bool {
	let aggregate_public_key = aggregate_ordered_keys(ordered_keys, &secp_context);

	let (effective_nonce, nonce_coefficient) = calculate_final_nonce(aggregate_public_nonce, &aggregate_public_key, message, &secp_context);
	let partial_nonce_summand = partial_public_nonce.1.mul_tweak(&secp_context, &nonce_coefficient).unwrap();
	let mut effective_partial_nonce = PublicKey::combine_keys(&[&partial_public_nonce.0, &partial_nonce_summand]).unwrap();
	if !has_even_y(&effective_nonce) {
		effective_partial_nonce = effective_partial_nonce.negate(&secp_context);
	}

	let m = tagged_hash_scalar("BIP0340/challenge", &[
		&effective_nonce.x_only_public_key().0.serialize(),
		&aggregate_public_key.key.serialize(),
		message
	]);

	// determine whether the aggregate public key has an even y coordinate
	let final_public_key = if let Parity::Even = aggregate_public_key.parity {
		partial_public_key.clone()
	} else {
		partial_public_key.negate(&secp_context)
	};

	let a = key_aggregation_coefficient(ordered_keys, partial_public_key);
	let summand = final_public_key.mul_tweak(&secp_context, &a).unwrap().mul_tweak(&secp_context, &m).unwrap();
	let equality_check = PublicKey::combine_keys(&[&summand, &effective_partial_nonce]).unwrap();

	let partial_signature_point = partial_signature.0.public_key(&secp_context);

	equality_check.serialize() == partial_signature_point.serialize()
}


fn tagged_sha_engine(tag: &str) -> ShaEngine {
	let tag_hash = Sha256::hash(tag.as_bytes()).to_byte_array();
	let mut sha_engine = Sha256::engine();
	sha_engine.input(&tag_hash);
	sha_engine.input(&tag_hash);
	sha_engine
}

fn tagged_hash_scalar(tag: &str, inputs: &[&[u8]]) -> Scalar {
	let mut sha_engine = tagged_sha_engine(tag);
	for current_input in inputs {
		sha_engine.input(current_input);
	}
	let output_hash = Sha256::from_engine(sha_engine).to_byte_array();
	Scalar::from_be_bytes(output_hash)
		.expect("SHA256 appears to be broken due to the heat death of the universe. If the user has a cat, please make sure to kill it.")
}


#[cfg(test)]
mod tests {
	use bitcoin::key::XOnlyPublicKey;

	use crate::key_preparation::aggregate_keys;
	use crate::nonce_preparation::aggregate_nonces;

	use super::*;

	fn verify_schnorr_signature(signature: &Signature, public_key: &PublicKey, message: &[u8]) -> bool {
		assert_eq!(signature.as_ref().len(), 64);

		let nonce_x = &signature[..32];
		let s = &signature[32..];

		let nonce = XOnlyPublicKey::from_slice(nonce_x).unwrap();
		let nonce = PublicKey::from_x_only_public_key(nonce, Parity::Even);

		let secp_context = Secp256k1::new();
		let s = SecretKey::from_slice(s).unwrap();
		let signature_point = s.public_key(&secp_context);
		assert!(has_even_y(&signature_point));

		let m = tagged_hash_scalar("BIP0340/challenge", &[
			&nonce.x_only_public_key().0.serialize(),
			&public_key.x_only_public_key().0.serialize(),
			message
		]);

		let summand = public_key.mul_tweak(&secp_context, &m).unwrap();
		let equality_check = PublicKey::combine_keys(&[&summand, &nonce]).unwrap();

		equality_check.serialize() == signature_point.serialize()
	}

	#[test]
	fn test_signature_aggregation() {
		let pubkey_hexes = vec![
			"03935f972da013f80ae011890fa89b67a27b7be6ccb24d3274d18b2d4067f261a9",
			"02d2dc6f5df7c56acf38c7fa0ae7a759ae30e19b37359dfde015872324c7ef6e05",
		];

		let public_nonce_hexes = vec![
			"0300a32f8548f59c533f55db9754e3c0ba3c2544f085649fdce42b8bd3f244c2ca0384449bed61004e8863452a38534e91875516c3cc543122ce2be1f31845025588",
			"03f66b072a869bc2a57d776d487151d707e82b4f1b885066a589858c1bf3871db603ed391c9658ab6031a96acbd5e2d9fec465efdc8c0d0b765c9b9f3579d520fb6f",
		];

		let partial_signature_hexes = vec![
			"7918521f42e5727fe2e82d802876e0c8844336fda1b58c82696a55b0188c8b3d",
			"599044037ae15c4a99fb94f022b48e7ab215bf703954ec0b83d0e06230476001",
		];

		let mut public_keys = Vec::with_capacity(pubkey_hexes.len());
		for current_pubkey_hex in pubkey_hexes {
			let current_key = PublicKey::from_slice(&hex::decode(current_pubkey_hex).unwrap()).unwrap();
			public_keys.push(current_key);
		}

		let mut public_nonces = Vec::with_capacity(public_nonce_hexes.len());
		for current_nonce_hex in public_nonce_hexes {
			let current_nonce = PublicNonce::from_slice(&hex::decode(current_nonce_hex).unwrap()).unwrap();
			public_nonces.push(current_nonce);
		}

		let mut partial_signatures = Vec::with_capacity(partial_signature_hexes.len());
		for current_signature_hex in partial_signature_hexes {
			let current_signature = SecretKey::from_slice(&hex::decode(current_signature_hex).unwrap()).unwrap();
			partial_signatures.push(PartialSignature(current_signature));
		}

		assert_eq!(public_keys.len(), 2);
		assert_eq!(public_nonces.len(), 2);
		assert_eq!(partial_signatures.len(), 2);

		let message = hex::decode("599c67ea410d005b9da90817cf03ed3b1c868e4da4edf00a5880b0082c237869").unwrap();

		let aggregate_nonce = aggregate_nonces(&public_nonces);
		let aggregate_nonce_hex = hex::encode(aggregate_nonce.serialize());
		assert_eq!(aggregate_nonce_hex, "02bc34cdf6fa1298d7b6a126812fad0739005bc44e45c21276eefe41aaf841c86f03f3562aed52243bb99f43d1677db59f0fefb961633997f7ac924b78fbd0b0334f");

		let secp_context = Secp256k1::new();
		{
			let ordered_public_keys = SignerPublicKeys::Ordered(public_keys.clone());
			let aggregate_public_key = aggregate_keys(&ordered_public_keys, &secp_context);
			println!("aggregate pubkey (Q): {}", hex::encode(aggregate_public_key.key.serialize()));

			let (final_nonce, _) = calculate_final_nonce(&aggregate_nonce, &aggregate_public_key, &message, &secp_context);
			println!("final nonce (R): {}", hex::encode(final_nonce.serialize()));

			let signature = aggregate_partial_signatures(partial_signatures.as_slice(), &final_nonce);
			let signature_hex = hex::encode(signature.as_ref());
			assert_eq!(signature_hex, "ca3c28729659e50f829f55dc5db1de88a05d1702b4165b85f95b627fc57733f8d2a89622bdc6ceca7ce3c2704b2b6f433658f66ddb0a788ded3b361248d3eb3e")
		}
		{
			// experiment with sorted pub keys
			let reversed_public_keys = SignerPublicKeys::ToSort(public_keys.clone());
			let aggregate_public_key = aggregate_keys(&reversed_public_keys, &secp_context);
			println!("aggregate pubkey (Q, reversed order): {}", hex::encode(aggregate_public_key.key.serialize()));

			let (final_nonce, _) = calculate_final_nonce(&aggregate_nonce, &aggregate_public_key, &message, &secp_context);
			println!("final nonce (R): {}", hex::encode(final_nonce.serialize()));

			let signature = aggregate_partial_signatures(partial_signatures.as_slice(), &final_nonce);
			let signature_hex = hex::encode(signature.as_ref());
			assert_eq!(signature_hex, "13f2dba79042c42b8b25544c3b8d6785f170571a3b23e6c7d2997e94dbc04284d2a89622bdc6ceca7ce3c2704b2b6f433658f66ddb0a788ded3b361248d3eb3e")
		}
		{
			// experiment with explicitly reversed pub keys
			let reversed_public_keys = SignerPublicKeys::Ordered(vec![public_keys[1], public_keys[0]]);
			let aggregate_public_key = aggregate_keys(&reversed_public_keys, &secp_context);
			println!("aggregate pubkey (Q, reversed order): {}", hex::encode(aggregate_public_key.key.serialize()));

			let (final_nonce, _) = calculate_final_nonce(&aggregate_nonce, &aggregate_public_key, &message, &secp_context);
			println!("final nonce (R): {}", hex::encode(final_nonce.serialize()));

			let signature = aggregate_partial_signatures(partial_signatures.as_slice(), &final_nonce);
			let signature_hex = hex::encode(signature.as_ref());
			assert_eq!(signature_hex, "13f2dba79042c42b8b25544c3b8d6785f170571a3b23e6c7d2997e94dbc04284d2a89622bdc6ceca7ce3c2704b2b6f433658f66ddb0a788ded3b361248d3eb3e")
		}
	}

	#[test]
	fn test_signature_verification() {
		let secp_context = Secp256k1::new();

		let secret_keys = vec![
			SecretKey::from_slice(&hex::decode("d2dc6f5df7c56acf38c7fa0ae7a759ae30e19b37359dfde015872324c7ef6e05").unwrap()).unwrap(),
			SecretKey::from_slice(&hex::decode("935f972da013f80ae011890fa89b67a27b7be6ccb24d3274d18b2d4067f261a9").unwrap()).unwrap(),
		];

		let public_keys = vec![
			PublicKey::from_secret_key(&secp_context, &secret_keys[0]),
			PublicKey::from_secret_key(&secp_context, &secret_keys[1]),
		];

		let sortable_public_keys = SignerPublicKeys::ToSort(public_keys.clone());
		// let sorted_public_keys = public_keys.clone();


		let secret_nonce_hexes = vec![
			vec!["00a32f8548f59c533f55db9754e3c0ba3c2544f085649fdce42b8bd3f244c2ca", "0384449bed61004e8863452a38534e91875516c3cc543122ce2be1f318450255"],
			vec!["f66b072a869bc2a57d776d487151d707e82b4f1b885066a589858c1bf3871db6", "03ed391c9658ab6031a96acbd5e2d9fec465efdc8c0d0b765c9b9f3579d520fb"],
		];
		let mut secret_nonces = Vec::with_capacity(secret_nonce_hexes.len());
		for current_nonce_hex in secret_nonce_hexes {
			let nonce_a = SecretKey::from_slice(&hex::decode(current_nonce_hex[0]).unwrap()).unwrap();
			let nonce_b = SecretKey::from_slice(&hex::decode(current_nonce_hex[0]).unwrap()).unwrap();
			secret_nonces.push(SecretNonce(nonce_a, nonce_b));
		}

		let public_nonces = vec![
			secret_nonces[0].to_public(&secp_context),
			secret_nonces[1].to_public(&secp_context),
		];

		let aggregate_nonce = aggregate_nonces(public_nonces.as_slice());
		let aggregate_pubkey = aggregate_keys(&sortable_public_keys, &secp_context);
		let message = hex::decode("599c67ea410d005b9da90817cf03ed3b1c868e4da4edf00a5880b0082c237869").unwrap();
		let (effective_nonce, _) = calculate_final_nonce(&aggregate_nonce, &aggregate_pubkey, &message, &secp_context);

		let partial_signature_a = sign(&secret_keys[0], &secret_nonces[0], &aggregate_nonce, &sortable_public_keys, &message, &secp_context);
		let partial_signature_b = sign(&secret_keys[1], &secret_nonces[1], &aggregate_nonce, &sortable_public_keys, &message, &secp_context);

		let is_signature_a_valid = verify_partial_signature(&partial_signature_a, &public_nonces[0], &aggregate_nonce, &public_keys[0], &sortable_public_keys, &message, &secp_context);
		let is_signature_b_valid = verify_partial_signature(&partial_signature_b, &public_nonces[1], &aggregate_nonce, &public_keys[1], &sortable_public_keys, &message, &secp_context);

		assert!(is_signature_a_valid);
		assert!(is_signature_b_valid);

		let schnorr_signature = aggregate_partial_signatures(&[partial_signature_a, partial_signature_b], &effective_nonce);
		let is_schnorr_signature_valid = verify_schnorr_signature(&schnorr_signature, &PublicKey::from_x_only_public_key(aggregate_pubkey.key, Parity::Even), &message);
		assert!(is_schnorr_signature_valid)
	}

	#[test]
	fn test_signature_verification_against_vectors() {
		let secp_context = Secp256k1::new();

		let secret_key_hex = "7fb9e0e687ada1eebf7ecfe2f21e73ebdb51a7d450948dfe8d76d7f2d1007671";
		let pubkey_hexes = vec![
			"03935f972da013f80ae011890fa89b67a27b7be6ccb24d3274d18b2d4067f261a9",
			"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
			"02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba661",
		];

		let secret_nonce_hex = "508b81a611f100a6b2b6b29656590898af488bcf2e1f55cf22e5cfb84421fe61fa27fd49b1d50085b481285e1ca205d55c82cc1b31ff5cd54a489829355901f7";
		let public_nonce_hexes = vec![
			"0337c87821afd50a8644d820a8f3e02e499c931865c2360fb43d0a0d20dafe07ea0287bf891d2a6deaebadc909352aa9405d1428c15f4b75f04dae642a95c2548480",
			"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			"032de2662628c90b03f5e720284eb52ff7d71f4284f627b68a853d78c78e1ffe9303e4c5524e83ffe1493b9077cf1ca6beb2090c93d930321071ad40b2f44e599046",
		];
		let aggregate_nonce_hex = "028465fcf0bbdbcf443aabcce533d42b4b5a10966ac09a49655e8c42daab8fcd61037496a3cc86926d452cafcfd55d25972ca1675d549310de296bff42f72eeea8c9";
		let message_hex = "f95466d086770e689964664219266fe5ed215c92ae20bab5c9d79addddf3c0cf";

		let secret_key = SecretKey::from_slice(&hex::decode(secret_key_hex).unwrap()).unwrap();

		let public_keys = vec![
			PublicKey::from_slice(&hex::decode(&pubkey_hexes[0]).unwrap()).unwrap(),
			PublicKey::from_slice(&hex::decode(&pubkey_hexes[1]).unwrap()).unwrap(),
			PublicKey::from_slice(&hex::decode(&pubkey_hexes[2]).unwrap()).unwrap(),
		];

		let secret_nonce_a = SecretKey::from_slice(&hex::decode(&secret_nonce_hex[..64]).unwrap()).unwrap();
		let secret_nonce_b = SecretKey::from_slice(&hex::decode(&secret_nonce_hex[64..]).unwrap()).unwrap();
		println!("nonce A pubkey: {}", hex::encode(secret_nonce_a.public_key(&secp_context).serialize()));
		println!("nonce B pubkey: {}", hex::encode(secret_nonce_b.public_key(&secp_context).serialize()));
		let secret_nonce = SecretNonce(secret_nonce_a, secret_nonce_b);

		let mut public_nonces = Vec::with_capacity(public_nonce_hexes.len());
		for current_nonce_hex in public_nonce_hexes {
			let current_nonce = PublicNonce::from_slice(&hex::decode(current_nonce_hex).unwrap()).unwrap();
			public_nonces.push(current_nonce);
		}

		let aggregate_nonce = PublicNonce::from_slice(&hex::decode(aggregate_nonce_hex).unwrap()).unwrap();

		let message = hex::decode(message_hex).unwrap();

		let ordered_public_keys = SignerPublicKeys::Ordered(public_keys);
		let partial_signature = sign(&secret_key, &secret_nonce, &aggregate_nonce, &ordered_public_keys, &message, &secp_context);
		assert_eq!(hex::encode(&partial_signature.0.secret_bytes()), "012abbcb52b3016ac03ad82395a1a415c48b93def78718e62a7a90052fe224fb");

		// let is_signature_valid = verify_partial_signature_internal(&partial_signature, &public_nonces[0], &aggregate_nonce, &public_keys[0], public_keys.as_slice(), &message);
		let is_signature_valid = verify_partial_signature(&partial_signature, &secret_nonce.to_public(&secp_context), &aggregate_nonce, &secret_key.public_key(&secp_context), &ordered_public_keys, &message, &secp_context);
		assert!(is_signature_valid);
	}
}
