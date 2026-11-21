use core::fmt::Write;

use crate::Error;
use crate::keccak::Keccak;

/// EIP-191 `personal_sign` message (version `0x45`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersonalMessage<'a>(&'a [u8]);

impl<'a> PersonalMessage<'a> {
	/// Wraps message bytes.
	pub const fn new(message: &'a [u8]) -> Self {
		Self(message)
	}

	/// Message bytes.
	pub const fn as_bytes(&self) -> &'a [u8] {
		self.0
	}

	/// Hash of `"\x19Ethereum Signed Message:\n" || len || message`.
	///
	/// # Errors
	///
	/// Returns [`Error::InvalidEncoding`] if the prefix cannot be formatted.
	pub fn signing_hash(&self) -> Result<[u8; 32], Error> {
		let mut hasher = Keccak::new();
		write!(hasher, "\x19Ethereum Signed Message:\n{}", self.0.len())
			.map_err(|_| Error::InvalidEncoding)?;
		hasher.update(self.0);
		Ok(hasher.finalize())
	}
}
