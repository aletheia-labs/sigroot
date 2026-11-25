use crate::Error;

const ORDER: [u8; 32] = [
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const HALF_ORDER: [u8; 32] = [
	0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Recoverable secp256k1 signature with low `s` (EIP-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
	r: [u8; 32],
	s: [u8; 32],
	y_parity: bool,
}

impl Signature {
	/// Validates signature components.
	///
	/// # Errors
	///
	/// Returns [`Error::InvalidSignature`] unless `0 < r < n` and `0 < s <= n / 2`.
	pub fn new(r: [u8; 32], s: [u8; 32], y_parity: bool) -> Result<Self, Error> {
		let zero = [0; 32];
		if r == zero || r >= ORDER || s == zero || s > HALF_ORDER {
			return Err(Error::InvalidSignature);
		}
		Ok(Self { r, s, y_parity })
	}

	/// Parses `r || s || v` with `v` in `{0, 1, 27, 28}`.
	///
	/// # Errors
	///
	/// Returns [`Error::InvalidSignature`] for any other `v` or invalid components.
	pub fn from_rsv(bytes: &[u8; 65]) -> Result<Self, Error> {
		let (r, rest) = bytes.split_first_chunk::<32>().ok_or(Error::InvalidSignature)?;
		let (s, v) = rest.split_first_chunk::<32>().ok_or(Error::InvalidSignature)?;
		let y_parity = match v {
			[0 | 27] => false,
			[1 | 28] => true,
			_ => return Err(Error::InvalidSignature),
		};
		Self::new(*r, *s, y_parity)
	}

	/// Encodes `r || s || v` with `v` in `{27, 28}`.
	pub fn to_rsv(&self) -> [u8; 65] {
		let v = [if self.y_parity { 28 } else { 27 }];
		let mut out = [0; 65];
		for (byte, value) in out.iter_mut().zip(self.r.iter().chain(&self.s).chain(&v)) {
			*byte = *value;
		}
		out
	}

	/// `r`, big-endian.
	pub const fn r(&self) -> &[u8; 32] {
		&self.r
	}

	/// `s`, big-endian.
	pub const fn s(&self) -> &[u8; 32] {
		&self.s
	}

	/// Parity of the `y` coordinate of the signature point.
	pub const fn y_parity(&self) -> bool {
		self.y_parity
	}
}

/// Raw 32-byte digest, signed without interpretation or policy.
#[cfg(feature = "unchecked-prehash")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UncheckedPrehash(pub [u8; 32]);

with_payload! {
	/// Typed payload accepted by a [`Signer`].
	#[non_exhaustive]
	#[derive(Clone, Copy, Debug)]
	pub enum Payload<'a> {
		/// EIP-191 `personal_sign` message.
		#[cfg(feature = "eip191")]
		PersonalMessage(&'a crate::PersonalMessage<'a>),
		/// Legacy EIP-155 transaction.
		#[cfg(feature = "tx-legacy")]
		Legacy(&'a crate::LegacyTx<'a>),
		/// EIP-2930 transaction.
		#[cfg(feature = "tx-eip2930")]
		Eip2930(&'a crate::Eip2930Tx<'a>),
		/// EIP-1559 transaction.
		#[cfg(feature = "tx-eip1559")]
		Eip1559(&'a crate::Eip1559Tx<'a>),
		/// Raw digest without interpretation.
		#[cfg(feature = "unchecked-prehash")]
		UncheckedPrehash(&'a UncheckedPrehash),
	}

	impl Payload<'_> {
		/// Hash signed for this payload.
		///
		/// # Errors
		///
		/// Returns an error if the payload cannot be encoded.
		pub fn signing_hash(&self) -> Result<[u8; 32], Error> {
			match self {
				#[cfg(feature = "eip191")]
				Self::PersonalMessage(message) => message.signing_hash(),
				#[cfg(feature = "tx-legacy")]
				Self::Legacy(tx) => tx.signing_hash(),
				#[cfg(feature = "tx-eip2930")]
				Self::Eip2930(tx) => tx.signing_hash(),
				#[cfg(feature = "tx-eip1559")]
				Self::Eip1559(tx) => tx.signing_hash(),
				#[cfg(feature = "unchecked-prehash")]
				Self::UncheckedPrehash(prehash) => Ok(prehash.0),
			}
		}
	}

	/// Produces signatures over typed payloads.
	pub trait Signer {
		/// Signs `payload`.
		///
		/// # Errors
		///
		/// Returns an error if the payload cannot be encoded or the signer refuses or fails.
		fn sign(&self, payload: Payload<'_>) -> Result<Signature, Error>;
	}
}
