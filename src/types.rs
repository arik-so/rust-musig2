//! Types used exclusively for MuSig2 shenanigans

use bitcoin::secp256k1::{Parity, PublicKey, Secp256k1, SecretKey};
use bitcoin::key::XOnlyPublicKey;

use core::hash::{Hash, Hasher};

/// A public nonce used for Musig2, comprised of two ECPoints
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicNonce(pub(crate) PublicKey, pub(crate) PublicKey);

/// A secret nonce used for Musig2, comprised of two SecretKeys
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretNonce(pub(crate) SecretKey, pub(crate) SecretKey);

impl Hash for SecretNonce {
	fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.secret_bytes().hash(state);
        self.1.secret_bytes().hash(state);
    }
}

/// A type representing an aggregated public key for MuSig2 use
pub struct AggregateKey {
	pub(crate) key: XOnlyPublicKey,
	pub(crate) parity: Parity
}

/// A partial MuSig2 signature
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialSignature(pub(crate) SecretKey);

impl Hash for PartialSignature {
	fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.secret_bytes().hash(state);
    }
}

/// A pubkey container that discriminates between preördered and sortable keys
pub enum SignerPublicKeys {
	/// These keys are ordered a priori
	Ordered(Vec<PublicKey>),
	/// These keys may or may not be ordered. Usage will automatically result in sorting.
	ToSort(Vec<PublicKey>)
}

impl SecretNonce {
	/// Convert to public
    pub fn to_public<C: bitcoin::secp256k1::Signing>(&self, secp_context: &Secp256k1<C>) -> PublicNonce {
        PublicNonce(
			PublicKey::from_secret_key(&secp_context, &self.0),
			PublicKey::from_secret_key(&secp_context, &self.1),
        )
    }

	/// Serialize the two private keys contained within
    pub fn serialize(&self) -> [u8; 64] {
        let mut serialization = [0; 64];
        let (first, second) = serialization.split_at_mut(32);
        first.copy_from_slice(&self.0.secret_bytes());
        second.copy_from_slice(&self.1.secret_bytes());
        serialization
    }

	/// Deserialize from bytes
    pub fn from_slice(data: &[u8]) -> Result<SecretNonce, bitcoin::secp256k1::Error> {
        assert_eq!(data.len(), 64, "SecretNonce can only be read from exactly 64 bytes");
        let first = SecretKey::from_slice(&data[0..32])?;
        let second = SecretKey::from_slice(&data[32..64])?;
        Ok(Self(first, second))
    }

    pub(crate) fn negate(&self) -> Self {
        let first_nonce = self.0.negate();
        let second_nonce = self.1.negate();
        SecretNonce(first_nonce, second_nonce)
    }
}

impl PublicNonce {
	/// Serialize the two public keys contained within
    pub fn serialize(&self) -> [u8; 66] {
        let mut serialization = [0; 66];
        let (first, second) = serialization.split_at_mut(33);
        first.copy_from_slice(&self.0.serialize());
        second.copy_from_slice(&self.1.serialize());
        serialization
    }

	/// Deserialize from bytes
    pub fn from_slice(data: &[u8]) -> Result<PublicNonce, bitcoin::secp256k1::Error> {
        assert_eq!(data.len(), 66, "PublicNonce can only be read from exactly 66 bytes");
        let first = PublicKey::from_slice(&data[0..33])?;
        let second = PublicKey::from_slice(&data[33..66])?;
        Ok(Self(first, second))
    }
}

impl PartialSignature {
	/// Serialize the scalar contained within
	pub fn serialize(&self) -> [u8; 32] {
		self.0.secret_bytes()
	}

	/// Deserialize from bytes
	pub fn from_slice(data: &[u8]) -> Result<PartialSignature, bitcoin::secp256k1::Error> {
		assert_eq!(data.len(), 32, "PartialSignature can only be read from exactly 32 bytes");
		let secret_key = SecretKey::from_slice(data)?;
		Ok(Self(secret_key))
	}
}

mod tests {
	#[test]
	fn test_public_types_derives() {
		#[derive(Clone, Debug, PartialEq, Eq, Hash)]
		struct Foo(super::PublicNonce, super::SecretNonce, super::PartialSignature);
	}
}
