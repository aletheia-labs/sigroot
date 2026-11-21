use core::fmt;

/// Errors returned by sigroot crates.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
	/// The entropy source failed.
	Entropy,
	/// An input has an invalid length.
	InvalidLength,
	/// An input is not a valid encoding.
	InvalidEncoding,
	/// A checksum does not match.
	InvalidChecksum,
	/// A key is not valid for its scheme.
	InvalidKey,
	/// A signature is malformed or does not verify.
	InvalidSignature,
	/// A derivation step produced no valid key.
	InvalidDerivation,
	/// The input is valid but outside the supported profile.
	Unsupported,
	/// An input exceeds an explicit size limit.
	LimitExceeded,
	/// An output buffer is too small.
	BufferTooSmall,
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Self::Entropy => "entropy source failed",
			Self::InvalidLength => "invalid length",
			Self::InvalidEncoding => "invalid encoding",
			Self::InvalidChecksum => "invalid checksum",
			Self::InvalidKey => "invalid key",
			Self::InvalidSignature => "invalid signature",
			Self::InvalidDerivation => "invalid derivation",
			Self::Unsupported => "unsupported",
			Self::LimitExceeded => "limit exceeded",
			Self::BufferTooSmall => "buffer too small",
		})
	}
}

impl core::error::Error for Error {}
