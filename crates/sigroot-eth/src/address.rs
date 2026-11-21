use core::fmt;

use crate::Error;
use crate::keccak::keccak256;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Ethereum address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address([u8; 20]);

impl Address {
	/// From raw bytes.
	pub const fn from_bytes(bytes: [u8; 20]) -> Self {
		Self(bytes)
	}

	/// Raw bytes.
	pub const fn as_bytes(&self) -> &[u8; 20] {
		&self.0
	}

	/// Address of an uncompressed public key given as `x || y`.
	pub fn from_public_key(xy: &[u8; 64]) -> Self {
		let hash = keccak256(xy);
		let mut bytes = [0; 20];
		for (out, byte) in bytes.iter_mut().zip(hash.iter().skip(12)) {
			*out = *byte;
		}
		Self(bytes)
	}

	/// Parses a `0x`-prefixed address with a valid EIP-55 checksum.
	///
	/// # Errors
	///
	/// Returns [`Error::InvalidEncoding`] for malformed input and [`Error::InvalidChecksum`] if
	/// the letter case does not match the EIP-55 checksum, including all-lowercase input.
	pub fn parse(s: &str) -> Result<Self, Error> {
		let digits = s.strip_prefix("0x").ok_or(Error::InvalidEncoding)?;
		if digits.len() != 40 {
			return Err(Error::InvalidEncoding);
		}
		let mut bytes = [0; 20];
		for (out, [high, low]) in bytes.iter_mut().zip(digits.as_bytes().as_chunks::<2>().0) {
			*out = nibble(*high)?.checked_shl(4).ok_or(Error::InvalidEncoding)? | nibble(*low)?;
		}
		let address = Self(bytes);
		if address.to_checksum() != s.as_bytes() {
			return Err(Error::InvalidChecksum);
		}
		Ok(address)
	}

	/// EIP-55 checksummed text, as ASCII.
	pub fn to_checksum(&self) -> [u8; 42] {
		let mut lower = [0; 40];
		for (pair, byte) in lower.as_chunks_mut::<2>().0.iter_mut().zip(self.0) {
			for (out, n) in pair.iter_mut().zip([byte >> 4, byte & 0x0f]) {
				*out = HEX.get(usize::from(n)).copied().unwrap_or(b'0');
			}
		}
		let hash = keccak256(&lower);
		let mut out = [0; 42];
		let (prefix, digits) = out.split_at_mut(2);
		prefix.copy_from_slice(b"0x");
		let nibbles = hash.iter().flat_map(|byte| [byte >> 4, byte & 0x0f]);
		for ((out, c), n) in digits.iter_mut().zip(lower).zip(nibbles) {
			*out = if n >= 8 { c.to_ascii_uppercase() } else { c };
		}
		out
	}
}

impl fmt::Display for Address {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(core::str::from_utf8(&self.to_checksum()).map_err(|_| fmt::Error)?)
	}
}

impl fmt::Debug for Address {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}

fn nibble(c: u8) -> Result<u8, Error> {
	char::from(c).to_digit(16).and_then(|d| u8::try_from(d).ok()).ok_or(Error::InvalidEncoding)
}
