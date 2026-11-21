use core::fmt;

use hmac::{Hmac, KeyInit, Mac};
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{FieldBytes, NonZeroScalar, PublicKey, Scalar};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Secret};

/// Offset of hardened child indices.
pub const HARDENED: u32 = 0x8000_0000;

/// Maximum number of components in a [`DerivationPath`].
pub const MAX_DEPTH: usize = 16;

/// BIP-32 derivation path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivationPath {
	indices: [u32; MAX_DEPTH],
	len: usize,
}

impl DerivationPath {
	/// Builds a path from child indices; hardened indices include [`HARDENED`].
	///
	/// # Errors
	///
	/// Returns [`Error::LimitExceeded`] for more than [`MAX_DEPTH`] components.
	pub fn new(indices: &[u32]) -> Result<Self, Error> {
		let mut path = Self { indices: [0; MAX_DEPTH], len: indices.len() };
		path.indices.get_mut(..indices.len()).ok_or(Error::LimitExceeded)?.copy_from_slice(indices);
		Ok(path)
	}

	/// Parses a path such as `m/44'/60'/0'/0/0`.
	///
	/// Hardened components use `'`. Leading zeros and other notations are rejected.
	///
	/// # Errors
	///
	/// Returns [`Error::InvalidEncoding`] for malformed paths and [`Error::LimitExceeded`] for
	/// more than [`MAX_DEPTH`] components.
	pub fn parse(path: &str) -> Result<Self, Error> {
		let mut parts = path.split('/');
		if parts.next() != Some("m") {
			return Err(Error::InvalidEncoding);
		}
		let mut indices = [0; MAX_DEPTH];
		let mut len = 0usize;
		for part in parts {
			let (digits, hardened) = match part.strip_suffix('\'') {
				Some(digits) => (digits, true),
				None => (part, false),
			};
			let canonical = !digits.is_empty()
				&& digits.bytes().all(|b| b.is_ascii_digit())
				&& (digits == "0" || !digits.starts_with('0'));
			if !canonical {
				return Err(Error::InvalidEncoding);
			}
			let index: u32 = digits.parse().map_err(|_| Error::InvalidEncoding)?;
			if index >= HARDENED {
				return Err(Error::InvalidEncoding);
			}
			*indices.get_mut(len).ok_or(Error::LimitExceeded)? =
				if hardened { index | HARDENED } else { index };
			len = len.checked_add(1).ok_or(Error::LimitExceeded)?;
		}
		Ok(Self { indices, len })
	}

	/// Child indices of the path.
	pub fn as_slice(&self) -> &[u32] {
		self.indices.get(..self.len).unwrap_or(&[])
	}
}

/// BIP-32 extended private key on secp256k1.
pub struct ExtendedPrivateKey {
	key: Secret<32>,
	chain_code: Secret<32>,
}

impl ExtendedPrivateKey {
	/// Derives the master key from a seed.
	///
	/// # Errors
	///
	/// Returns [`Error::InvalidLength`] unless the seed is 16 to 64 bytes, and
	/// [`Error::InvalidDerivation`] if the seed produces no valid key.
	pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
		if !(16..=64).contains(&seed.len()) {
			return Err(Error::InvalidLength);
		}
		let mut mac =
			Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").map_err(|_| Error::InvalidKey)?;
		mac.update(seed);
		let (key, chain_code) = split(mac)?;
		secret_scalar(key.expose())?;
		Ok(Self { key, chain_code })
	}

	/// Derives a child key; indices at or above [`HARDENED`] are hardened.
	///
	/// # Errors
	///
	/// Returns [`Error::InvalidDerivation`] if the index produces no valid key.
	pub fn derive_child(&self, index: u32) -> Result<Self, Error> {
		let parent = secret_scalar(self.key.expose())?;
		let mut mac = Hmac::<Sha512>::new_from_slice(self.chain_code.expose())
			.map_err(|_| Error::InvalidKey)?;
		if index >= HARDENED {
			mac.update(&[0]);
			mac.update(self.key.expose());
		} else {
			mac.update(PublicKey::from_secret_scalar(&parent).to_sec1_point(true).as_bytes());
		}
		mac.update(&index.to_be_bytes());
		let (tweak, chain_code) = split(mac)?;
		let tweak = scalar(tweak.expose()).ok_or(Error::InvalidDerivation)?;
		#[expect(
			clippy::arithmetic_side_effects,
			reason = "scalar addition is modulo the curve order"
		)]
		let child = Zeroizing::new(*tweak + **parent);
		let child = NonZeroScalar::new(*child)
			.into_option()
			.map(Zeroizing::new)
			.ok_or(Error::InvalidDerivation)?;
		let mut key = Secret::zeroed();
		let mut repr = child.to_repr();
		key.expose_mut().copy_from_slice(&repr);
		repr.as_mut_slice().zeroize();
		Ok(Self { key, chain_code })
	}

	/// Derives the key at `path`, relative to this key.
	///
	/// # Errors
	///
	/// Returns [`Error::InvalidDerivation`] if any step produces no valid key.
	pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, Error> {
		let mut indices = path.as_slice().iter();
		let Some(&first) = indices.next() else {
			return Ok(Self {
				key: Secret::new(*self.key.expose()),
				chain_code: Secret::new(*self.chain_code.expose()),
			});
		};
		let mut key = self.derive_child(first)?;
		for &index in indices {
			key = key.derive_child(index)?;
		}
		Ok(key)
	}

	/// Private key.
	pub const fn private_key(&self) -> &Secret<32> {
		&self.key
	}

	/// Chain code.
	pub const fn chain_code(&self) -> &Secret<32> {
		&self.chain_code
	}
}

impl fmt::Debug for ExtendedPrivateKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("ExtendedPrivateKey([REDACTED])")
	}
}

fn split(mac: Hmac<Sha512>) -> Result<(Secret<32>, Secret<32>), Error> {
	let mut out = mac.finalize().into_bytes();
	let halves = out
		.as_slice()
		.split_first_chunk::<32>()
		.and_then(|(left, right)| Some((*left, *right.first_chunk::<32>()?)));
	out.as_mut_slice().zeroize();
	let (left, right) = halves.ok_or(Error::InvalidLength)?;
	Ok((Secret::new(left), Secret::new(right)))
}

fn scalar(bytes: &[u8; 32]) -> Option<Zeroizing<Scalar>> {
	let mut repr = FieldBytes::from(*bytes);
	let scalar = Scalar::from_repr(repr).into_option().map(Zeroizing::new);
	repr.as_mut_slice().zeroize();
	scalar
}

fn secret_scalar(bytes: &[u8; 32]) -> Result<Zeroizing<NonZeroScalar>, Error> {
	let scalar = scalar(bytes).ok_or(Error::InvalidDerivation)?;
	NonZeroScalar::new(*scalar).into_option().map(Zeroizing::new).ok_or(Error::InvalidDerivation)
}
