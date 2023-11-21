use std::borrow::Borrow;

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1};

use crate::{AggregateKey, tagged_hash_scalar, tagged_sha_engine};
use crate::types::SignerPublicKeys;

/// Aggregate individual 33-byte public keys into the final 32-byte MuSig2 public key
pub fn aggregate_keys<C: bitcoin::secp256k1::Verification>(keys: &SignerPublicKeys, secp_context: &Secp256k1<C>) -> AggregateKey {
	let ordered_keys = keys.ordered_keys();
	aggregate_ordered_keys(&ordered_keys, secp_context)
}

pub(crate) fn aggregate_ordered_keys<K: Borrow<PublicKey>, C: bitcoin::secp256k1::Verification>(ordered_keys: &[K], secp_context: &Secp256k1<C>) -> AggregateKey {
	let mut key_summands = Vec::with_capacity(ordered_keys.len());

	for i in 0..ordered_keys.len() {
		let current_key = ordered_keys[i].borrow();
		let current_coefficient = key_aggregation_coefficient(&ordered_keys, &current_key);

		let current_summand = current_key.mul_tweak(&secp_context, &current_coefficient).unwrap();

		key_summands.push(current_summand);
	}

	let summand_references: Vec<&PublicKey> = key_summands.iter().collect();
	let combined_pubkey = PublicKey::combine_keys(&summand_references).unwrap();
	let (key, parity) = combined_pubkey.x_only_public_key();
	AggregateKey{ key, parity }
}

pub(super) fn has_even_y(public_key: &PublicKey) -> bool {
	let first_byte = public_key.serialize()[0];
	assert!([2, 3].contains(&first_byte));
	first_byte == 2
}

impl SignerPublicKeys {
	pub(crate) fn ordered_keys(&self) -> Vec<&PublicKey> {
		match &self {
			Self::Ordered(keys) => {
				keys.iter().collect::<Vec<_>>()
			}
			Self::ToSort(keys) => {
				let mut sorted_keys = keys.iter().collect::<Vec<_>>();
				sorted_keys.sort_by(|key_a, key_b| {
					let slice_a = key_a.serialize();
					let slice_b = key_b.serialize();
					slice_a.cmp(&slice_b)
				});
				sorted_keys
			}
		}
	}
}

fn hash_keys<K: Borrow<PublicKey>>(sorted_keys: &[K]) -> [u8; 32] {
	let mut sha_engine = tagged_sha_engine("KeyAgg list");
	for current_key in sorted_keys {
		sha_engine.input(&current_key.borrow().serialize());
	}
	Sha256::from_engine(sha_engine).to_byte_array()
}

fn second_key_serialization<K: Borrow<PublicKey>>(ordered_keys: &[K]) -> [u8; 33] {
	let first_key = ordered_keys[0].borrow();
	for j in 1..ordered_keys.len() {
		let current_key = ordered_keys[j].borrow();
		if current_key != first_key {
			return current_key.serialize();
		}
	}
	[0; 33]
}

pub(super) fn key_aggregation_coefficient<K: Borrow<PublicKey>>(ordered_keys: &[K], public_key: &PublicKey) -> Scalar {
	// could be memoized
	let second_key = second_key_serialization(ordered_keys);
	let referenced_key = public_key.serialize();
	if referenced_key == second_key {
		return Scalar::ONE;
	}

	// could be memoized
	let key_list_hash = hash_keys(ordered_keys);
	tagged_hash_scalar("KeyAgg coefficient", &[&key_list_hash, &referenced_key])
}

#[cfg(test)]
mod tests {
	use bitcoin::secp256k1::{PublicKey, Secp256k1};

	use crate::{key_aggregation_coefficient, SignerPublicKeys};
	use crate::key_preparation::aggregate_keys;

	#[test]
	fn test_key_sorting() {
		let unsorted_keys = vec![
			PublicKey::from_slice(&hex::decode("02dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8").unwrap()).unwrap(),
			PublicKey::from_slice(&hex::decode("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9").unwrap()).unwrap(),
			PublicKey::from_slice(&hex::decode("03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659").unwrap()).unwrap(),
			PublicKey::from_slice(&hex::decode("023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66").unwrap()).unwrap(),
			PublicKey::from_slice(&hex::decode("02dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8").unwrap()).unwrap(),
		];

		let sortable_keys = SignerPublicKeys::ToSort(unsorted_keys);
		let sorted_keys = sortable_keys.ordered_keys();

		assert_eq!(hex::encode(sorted_keys[0].serialize()), "023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66");
		assert_eq!(hex::encode(sorted_keys[1].serialize()), "02dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8");
		assert_eq!(hex::encode(sorted_keys[2].serialize()), "02dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8");
		assert_eq!(hex::encode(sorted_keys[3].serialize()), "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
		assert_eq!(hex::encode(sorted_keys[4].serialize()), "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659");
	}

	#[test]
	fn test_key_aggregation_coefficient_on_distinct_key() {
		let keys = vec![
			PublicKey::from_slice(&hex::decode("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9").unwrap()).unwrap(),
			PublicKey::from_slice(&hex::decode("03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659").unwrap()).unwrap(),
			PublicKey::from_slice(&hex::decode("023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66").unwrap()).unwrap(),
		];

		let coefficients = [
			key_aggregation_coefficient(&keys, &keys[0]),
			key_aggregation_coefficient(&keys, &keys[1]),
			key_aggregation_coefficient(&keys, &keys[2]),
		];

		assert_eq!(hex::encode(coefficients[0].to_be_bytes()), "ad0537c883813849e3b95ce5db1d45eb25cc5fae197c4e8759719065932aa183");
		assert_eq!(hex::encode(coefficients[1].to_be_bytes()), "0000000000000000000000000000000000000000000000000000000000000001");
		assert_eq!(hex::encode(coefficients[2].to_be_bytes()), "f45bb025038e68f050ce4dbf8c63e613678892e2a3e930780afe6293376005c6");
	}

	#[test]
	fn test_key_aggregation_coefficient_on_repeated_key() {
		let keys = vec![
			PublicKey::from_slice(&hex::decode("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9").unwrap()).unwrap(),
			PublicKey::from_slice(&hex::decode("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9").unwrap()).unwrap(),
			PublicKey::from_slice(&hex::decode("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9").unwrap()).unwrap(),
		];

		let coefficients = [
			key_aggregation_coefficient(&keys, &keys[0]),
			key_aggregation_coefficient(&keys, &keys[1]),
			key_aggregation_coefficient(&keys, &keys[2]),
		];

		assert_eq!(hex::encode(coefficients[0].to_be_bytes()), "d18a55755a3b6aa3b171bd484eb508318abd01a3cd5e6c78aca613dbd72fa061");
		assert_eq!(hex::encode(coefficients[1].to_be_bytes()), "d18a55755a3b6aa3b171bd484eb508318abd01a3cd5e6c78aca613dbd72fa061");
		assert_eq!(hex::encode(coefficients[2].to_be_bytes()), "d18a55755a3b6aa3b171bd484eb508318abd01a3cd5e6c78aca613dbd72fa061");

		let secp_context = Secp256k1::new();
		let aggregate_key = aggregate_keys(&SignerPublicKeys::Ordered(keys), &secp_context);
		assert_eq!(hex::encode(aggregate_key.key.serialize()), "b436e3bad62b8cd409969a224731c193d051162d8c5ae8b109306127da3aa935");
	}
}
