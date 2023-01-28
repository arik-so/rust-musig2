//! Types used exclusively for MuSig2 shenanigans

use bitcoin::secp256k1::{Parity, PublicKey, Secp256k1, SecretKey};
use bitcoin::XOnlyPublicKey;

/// A public nonce used for Musig2, comprised of two ECPoints
#[derive(Clone, Debug, PartialEq)]
pub struct PublicNonce(pub(crate) PublicKey, pub(crate) PublicKey);

/// A secret nonce used for Musig2, comprised of two SecretKeys
#[derive(Clone, Debug, PartialEq)]
pub struct SecretNonce(pub(crate) SecretKey, pub(crate) SecretKey);

pub(crate) type AggregateKey = (XOnlyPublicKey, Parity);
pub(crate) type PartialSignature = SecretKey;

impl SecretNonce {
    pub fn to_public(&self) -> PublicNonce {
        let secp = Secp256k1::new();
        PublicNonce(
            PublicKey::from_secret_key(&secp, &self.0),
            PublicKey::from_secret_key(&secp, &self.1),
        )
    }

    pub fn serialize(&self) -> [u8; 64] {
        let mut serialization = [0; 64];
        let (first, second) = serialization.split_at_mut(32);
        first.copy_from_slice(&self.0.secret_bytes());
        second.copy_from_slice(&self.1.secret_bytes());
        serialization
    }

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

impl Into<PublicNonce> for SecretNonce {
    fn into(self) -> PublicNonce {
        self.to_public()
    }
}

impl PublicNonce {
    pub fn serialize(&self) -> [u8; 66] {
        let mut serialization = [0; 66];
        let (first, second) = serialization.split_at_mut(33);
        first.copy_from_slice(&self.0.serialize());
        second.copy_from_slice(&self.1.serialize());
        serialization
    }

    pub fn from_slice(data: &[u8]) -> Result<PublicNonce, bitcoin::secp256k1::Error> {
        assert_eq!(data.len(), 66, "SecretNonce can only be read from exactly 66 bytes");
        let first = PublicKey::from_slice(&data[0..33])?;
        let second = PublicKey::from_slice(&data[33..66])?;
        Ok(Self(first, second))
    }
}
