/// 256-bit unsigned integer, stored big-endian.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct U256([u8; 32]);

impl U256 {
	/// Zero.
	pub const ZERO: Self = Self([0; 32]);

	/// Largest value.
	pub const MAX: Self = Self([0xff; 32]);

	/// From big-endian bytes.
	pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Big-endian bytes.
	pub const fn to_be_bytes(self) -> [u8; 32] {
		self.0
	}

	/// Big-endian bytes, borrowed.
	pub const fn as_be_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

impl From<u128> for U256 {
	fn from(value: u128) -> Self {
		let mut bytes = [0; 32];
		for (out, byte) in bytes.iter_mut().skip(16).zip(value.to_be_bytes()) {
			*out = byte;
		}
		Self(bytes)
	}
}

impl From<u64> for U256 {
	fn from(value: u64) -> Self {
		Self::from(u128::from(value))
	}
}
