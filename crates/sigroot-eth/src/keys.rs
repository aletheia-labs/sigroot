use core::fmt;

use zeroize::Zeroize;

use crate::{Address, Entropy, Error, PublicKey, Secret};

/// In-memory secp256k1 signing key.
pub struct SigningKey(k256::ecdsa::SigningKey);

impl SigningKey {
	/// Imports a private key.
	///
	/// # Errors
	///
	/// Returns [`Error::InvalidKey`] unless the key is in `[1, n)`.
	pub fn from_secret(secret: &Secret<32>) -> Result<Self, Error> {
		k256::ecdsa::SigningKey::from_slice(secret.expose())
			.map(Self)
			.map_err(|_| Error::InvalidKey)
	}

	/// Generates a key with fresh entropy.
	///
	/// # Errors
	///
	/// Returns [`Error::Entropy`] if the entropy source fails, and [`Error::InvalidKey`] if it
	/// produced an out-of-range key.
	pub fn generate(entropy: &mut impl Entropy) -> Result<Self, Error> {
		let mut secret = Secret::<32>::zeroed();
		entropy.fill(secret.expose_mut())?;
		Self::from_secret(&secret)
	}

	/// Exports the private key.
	pub fn to_secret(&self) -> Secret<32> {
		let mut bytes = self.0.to_bytes();
		let secret = Secret::new(bytes.into());
		bytes.as_mut_slice().zeroize();
		secret
	}

	/// Public key.
	pub fn public_key(&self) -> PublicKey {
		PublicKey((*self.0.verifying_key()).into())
	}

	/// Ethereum address.
	pub fn address(&self) -> Address {
		self.public_key().address()
	}
}

impl fmt::Debug for SigningKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("SigningKey([REDACTED])")
	}
}

with_payload! {
	impl crate::Signer for SigningKey {
		fn sign(&self, payload: crate::Payload<'_>) -> Result<crate::Signature, Error> {
			let hash = payload.signing_hash()?;
			let (signature, id) = self.0.sign_prehash_recoverable(&hash);
			if id.is_x_reduced() {
				return Err(Error::InvalidSignature);
			}
			let (r, s) = signature.split_bytes();
			crate::Signature::new(r.into(), s.into(), id.is_y_odd())
		}
	}
}
