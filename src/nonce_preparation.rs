use std::borrow::Borrow;

use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1};
use bitcoin::key::XOnlyPublicKey;

use crate::{AggregateKey, PublicNonce, tagged_hash_scalar};

/// Aggregate individual MuSig2 nonces into the final Schnorr signature nonce
pub fn aggregate_nonces<N: Borrow<PublicNonce>>(nonces: &[N]) -> PublicNonce {
	let mut first_nonce_summands = Vec::with_capacity(nonces.len());
	let mut second_nonce_summands = Vec::with_capacity(nonces.len());

	for current_nonce in nonces {
		let first_nonce = &current_nonce.borrow().0;
		let second_nonce = &current_nonce.borrow().1;

		first_nonce_summands.push(first_nonce);
		second_nonce_summands.push(second_nonce);
	}

	let first_nonce = PublicKey::combine_keys(&first_nonce_summands).unwrap();
	let second_nonce = PublicKey::combine_keys(&second_nonce_summands).unwrap();
	PublicNonce(first_nonce, second_nonce)
}

pub(crate) fn calculate_final_nonce<C: bitcoin::secp256k1::Verification>(aggregate_nonce: &PublicNonce, aggregate_public_key: &AggregateKey, message: &[u8], secp_context: &Secp256k1<C>) -> (PublicKey, Scalar) {
	let nonce_coefficient = nonce_linear_combination_coefficient(&aggregate_public_key.key, &aggregate_nonce, message);
	let nonce_summand = aggregate_nonce.1.mul_tweak(&secp_context, &nonce_coefficient).unwrap();
	let public_nonce = PublicKey::combine_keys(&[&aggregate_nonce.0, &nonce_summand]).unwrap();
	(public_nonce, nonce_coefficient)
}

fn nonce_linear_combination_coefficient(aggregate_public_key: &XOnlyPublicKey, aggregate_nonce: &PublicNonce, message: &[u8]) -> Scalar {
	tagged_hash_scalar("MuSig/noncecoef", &[&aggregate_nonce.serialize(), &aggregate_public_key.serialize(), message])
}

#[cfg(test)]
mod tests {
	use crate::nonce_preparation::aggregate_nonces;
	use crate::PublicNonce;

	#[test]
	fn test_nonce_aggregation() {
		let public_nonce_hexes = vec![
			"020151c80f435648df67a22b749cd798ce54e0321d034b92b709b567d60a42e66603ba47fbc1834437b3212e89a84d8425e7bf12e0245d98262268ebdcb385d50641",
			"03ff406ffd8adb9cd29877e4985014f66a59f6cd01c0e88caa8e5f3166b1f676a60248c264cdd57d3c24d79990b0f865674eb62a0f9018277a95011b41bfc193b833",
		];

		let mut public_nonces = Vec::with_capacity(public_nonce_hexes.len());
		for current_nonce_hex in public_nonce_hexes {
			let current_nonce = PublicNonce::from_slice(&hex::decode(current_nonce_hex).unwrap()).unwrap();
			public_nonces.push(current_nonce);
		}

		assert_eq!(public_nonces.len(), 2);

		let aggregate_nonce = aggregate_nonces(&public_nonces);
		let mut aggregate_nonce_bytes = Vec::with_capacity(66);
		aggregate_nonce_bytes.extend_from_slice(&aggregate_nonce.serialize());
		let aggregate_nonce_hex = hex::encode(aggregate_nonce_bytes);

		assert_eq!(aggregate_nonce_hex, "035fe1873b4f2967f52fea4a06ad5a8eccbe9d0fd73068012c894e2e87ccb5804b024725377345bde0e9c33af3c43c0a29a9249f2f2956fa8cfeb55c8573d0262dc8")
	}

	#[test]
	#[should_panic]
	// TODO: make it such that this doesn't panic
	fn test_nonce_aggregation_at_infinity_point() {
		let public_nonce_hexes = vec![
			"020151c80f435648df67a22b749cd798ce54e0321d034b92b709b567d60a42e6660279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			"03ff406ffd8adb9cd29877e4985014f66a59f6cd01c0e88caa8e5f3166b1f676a60379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		];

		let mut public_nonces = Vec::with_capacity(public_nonce_hexes.len());
		for current_nonce_hex in public_nonce_hexes {
			let current_nonce = PublicNonce::from_slice(&hex::decode(current_nonce_hex).unwrap()).unwrap();
			public_nonces.push(current_nonce);
		}

		assert_eq!(public_nonces.len(), 2);

		let aggregate_nonce = aggregate_nonces(&public_nonces);
		let mut aggregate_nonce_bytes = Vec::with_capacity(66);
		aggregate_nonce_bytes.extend_from_slice(&aggregate_nonce.serialize());
		let aggregate_nonce_hex = hex::encode(aggregate_nonce_bytes);

		assert_eq!(aggregate_nonce_hex, "035fe1873b4f2967f52fea4a06ad5a8eccbe9d0fd73068012c894e2e87ccb5804b000000000000000000000000000000000000000000000000000000000000000000")
	}
}
