use k256::elliptic_curve::sec1::ToSec1Point;

use crate::{Address, Error};

/// secp256k1 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub(crate) k256::PublicKey);

impl PublicKey {
	/// Parses a compressed (33 bytes) or uncompressed (65 bytes) SEC1 key.
	///
	/// # Errors
	///
	/// Returns [`Error::InvalidKey`] if the bytes are not a valid point.
	pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, Error> {
		if !matches!(bytes.len(), 33 | 65) {
			return Err(Error::InvalidKey);
		}
		k256::PublicKey::from_sec1_bytes(bytes).map(Self).map_err(|_| Error::InvalidKey)
	}

	/// Uncompressed SEC1 encoding.
	pub fn to_uncompressed(&self) -> [u8; 65] {
		let mut out = [0; 65];
		copy(&mut out, self.0.to_sec1_point(false).as_bytes());
		out
	}

	/// Compressed SEC1 encoding.
	pub fn to_compressed(&self) -> [u8; 33] {
		let mut out = [0; 33];
		copy(&mut out, self.0.to_sec1_point(true).as_bytes());
		out
	}

	/// Ethereum address of this key.
	pub fn address(&self) -> Address {
		let mut xy = [0; 64];
		copy(&mut xy, self.to_uncompressed().get(1..).unwrap_or(&[]));
		Address::from_public_key(&xy)
	}
}

fn copy(out: &mut [u8], bytes: &[u8]) {
	for (out, byte) in out.iter_mut().zip(bytes) {
		*out = *byte;
	}
}

#[cfg(feature = "verify")]
with_payload! {
	impl crate::Signature {
		/// Recovers the public key that produced this signature over `payload`.
		///
		/// # Errors
		///
		/// Returns [`Error::InvalidSignature`] if no key can be recovered.
		pub fn recover(&self, payload: crate::Payload<'_>) -> Result<PublicKey, Error> {
			use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

			let hash = payload.signing_hash()?;
			let signature =
				Signature::from_scalars(*self.r(), *self.s()).map_err(|_| Error::InvalidSignature)?;
			let id = RecoveryId::new(self.y_parity(), false);
			let key = VerifyingKey::recover_from_prehash(&hash, &signature, id)
				.map_err(|_| Error::InvalidSignature)?;
			Ok(PublicKey(key.into()))
		}
	}

	impl PublicKey {
		/// Checks that `signature` over `payload` was produced by this key.
		///
		/// # Errors
		///
		/// Returns [`Error::InvalidSignature`] otherwise.
		pub fn verify(
			&self,
			payload: crate::Payload<'_>,
			signature: &crate::Signature,
		) -> Result<(), Error> {
			if signature.recover(payload)? == *self { Ok(()) } else { Err(Error::InvalidSignature) }
		}
	}
}
