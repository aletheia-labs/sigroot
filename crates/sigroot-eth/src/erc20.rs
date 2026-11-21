use crate::{Address, Error, U256};

const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

/// ERC-20 call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erc20Call {
	/// `transfer(address,uint256)`.
	Transfer {
		/// Recipient.
		to: Address,
		/// Token amount.
		amount: U256,
	},
	/// `transferFrom(address,address,uint256)`.
	TransferFrom {
		/// Token owner.
		from: Address,
		/// Recipient.
		to: Address,
		/// Token amount.
		amount: U256,
	},
	/// `approve(address,uint256)`.
	Approve {
		/// Allowed spender.
		spender: Address,
		/// Allowance.
		amount: U256,
	},
}

impl Erc20Call {
	/// Decodes call data with canonical ABI encoding.
	///
	/// # Errors
	///
	/// Returns [`Error::Unsupported`] for an unknown selector and [`Error::InvalidEncoding`] for
	/// wrong length or non-zero address padding.
	pub fn decode(input: &[u8]) -> Result<Self, Error> {
		let (selector, args) = input.split_first_chunk::<4>().ok_or(Error::InvalidEncoding)?;
		match *selector {
			TRANSFER => {
				let [to, amount] = words(args)?;
				Ok(Self::Transfer { to: address(to)?, amount: U256::from_be_bytes(*amount) })
			},
			TRANSFER_FROM => {
				let [from, to, amount] = words(args)?;
				Ok(Self::TransferFrom {
					from: address(from)?,
					to: address(to)?,
					amount: U256::from_be_bytes(*amount),
				})
			},
			APPROVE => {
				let [spender, amount] = words(args)?;
				Ok(Self::Approve {
					spender: address(spender)?,
					amount: U256::from_be_bytes(*amount),
				})
			},
			_ => Err(Error::Unsupported),
		}
	}

	/// Length of the call data.
	pub const fn encoded_len(&self) -> usize {
		match self {
			Self::Transfer { .. } | Self::Approve { .. } => 68,
			Self::TransferFrom { .. } => 100,
		}
	}

	/// Writes the call data into `buf` and returns its length.
	///
	/// # Errors
	///
	/// Returns [`Error::BufferTooSmall`] if `buf` is too short.
	pub fn encode(&self, buf: &mut [u8]) -> Result<usize, Error> {
		let len = self.encoded_len();
		let out = buf.get_mut(..len).ok_or(Error::BufferTooSmall)?;
		out.fill(0);
		let (selector, addresses, amount) = match self {
			Self::Transfer { to, amount } => (TRANSFER, [Some(to), None], amount),
			Self::TransferFrom { from, to, amount } => {
				(TRANSFER_FROM, [Some(from), Some(to)], amount)
			},
			Self::Approve { spender, amount } => (APPROVE, [Some(spender), None], amount),
		};
		let (head, words) = out.split_first_chunk_mut::<4>().ok_or(Error::BufferTooSmall)?;
		*head = selector;
		let mut words = words.as_chunks_mut::<32>().0.iter_mut();
		for address in addresses.into_iter().flatten() {
			let word = words.next().ok_or(Error::BufferTooSmall)?;
			word.get_mut(12..).ok_or(Error::BufferTooSmall)?.copy_from_slice(address.as_bytes());
		}
		words.next().ok_or(Error::BufferTooSmall)?.copy_from_slice(amount.as_be_bytes());
		Ok(len)
	}
}

fn words<const N: usize>(args: &[u8]) -> Result<&[[u8; 32]; N], Error> {
	let (words, rest) = args.as_chunks::<32>();
	if !rest.is_empty() {
		return Err(Error::InvalidEncoding);
	}
	words.try_into().map_err(|_| Error::InvalidEncoding)
}

fn address(word: &[u8; 32]) -> Result<Address, Error> {
	let (padding, bytes) = word.split_first_chunk::<12>().ok_or(Error::InvalidEncoding)?;
	if *padding != [0; 12] {
		return Err(Error::InvalidEncoding);
	}
	Ok(Address::from_bytes(bytes.try_into().map_err(|_| Error::InvalidEncoding)?))
}
