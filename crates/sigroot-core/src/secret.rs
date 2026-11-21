use core::fmt;

use zeroize::Zeroize;

/// Fixed-size secret bytes, zeroized on drop.
///
/// Not `Clone`, not `Copy`, and `Debug` is redacted. Copies made by the caller before wrapping, or
/// by the compiler when moving the value, are outside its control.
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
	/// Wraps secret bytes.
	pub const fn new(bytes: [u8; N]) -> Self {
		Self(bytes)
	}

	/// Returns a secret filled with zeros, to be written in place.
	pub const fn zeroed() -> Self {
		Self([0; N])
	}

	/// Returns the secret bytes.
	pub const fn expose(&self) -> &[u8; N] {
		&self.0
	}

	/// Returns the secret bytes for writing in place.
	pub const fn expose_mut(&mut self) -> &mut [u8; N] {
		&mut self.0
	}
}

impl<const N: usize> Drop for Secret<N> {
	fn drop(&mut self) {
		self.0.zeroize();
	}
}

impl<const N: usize> fmt::Debug for Secret<N> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("Secret([REDACTED])")
	}
}
