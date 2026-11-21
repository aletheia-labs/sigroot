use core::fmt;

use hmac::Hmac;
use sha2::{Digest, Sha256, Sha512};
#[cfg(feature = "nfkd")]
use unicode_normalization::char::{canonical_combining_class, decompose_compatible};
use zeroize::Zeroize;
#[cfg(feature = "nfkd")]
use zeroize::Zeroizing;

use crate::{Entropy, Error, Secret, Seed};

const WORDLIST: &str = include_str!("english.txt");
const MAX_WORDS: usize = 24;
const MAX_SENTENCE_LEN: usize = 215;
const SALT_PREFIX: &[u8] = b"mnemonic";
const SALT_CAPACITY: usize = 264;
const ROUNDS: u32 = 2048;

/// Maximum passphrase length in bytes, after NFKD normalization.
pub const MAX_PASSPHRASE_LEN: usize = 256;

/// Number of words in a mnemonic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordCount {
	/// 12 words, 128 bits of entropy.
	W12,
	/// 15 words, 160 bits of entropy.
	W15,
	/// 18 words, 192 bits of entropy.
	W18,
	/// 21 words, 224 bits of entropy.
	W21,
	/// 24 words, 256 bits of entropy.
	W24,
}

impl WordCount {
	/// Number of words.
	pub const fn words(self) -> usize {
		match self {
			Self::W12 => 12,
			Self::W15 => 15,
			Self::W18 => 18,
			Self::W21 => 21,
			Self::W24 => 24,
		}
	}

	/// Entropy length in bytes.
	pub const fn entropy_len(self) -> usize {
		match self {
			Self::W12 => 16,
			Self::W15 => 20,
			Self::W18 => 24,
			Self::W21 => 28,
			Self::W24 => 32,
		}
	}

	const fn checksum_bits(self) -> u32 {
		match self {
			Self::W12 => 4,
			Self::W15 => 5,
			Self::W18 => 6,
			Self::W21 => 7,
			Self::W24 => 8,
		}
	}

	const fn from_words(words: usize) -> Result<Self, Error> {
		match words {
			12 => Ok(Self::W12),
			15 => Ok(Self::W15),
			18 => Ok(Self::W18),
			21 => Ok(Self::W21),
			24 => Ok(Self::W24),
			_ => Err(Error::InvalidLength),
		}
	}

	const fn from_entropy_len(len: usize) -> Result<Self, Error> {
		match len {
			16 => Ok(Self::W12),
			20 => Ok(Self::W15),
			24 => Ok(Self::W18),
			28 => Ok(Self::W21),
			32 => Ok(Self::W24),
			_ => Err(Error::InvalidLength),
		}
	}
}

/// BIP-39 mnemonic using the English wordlist.
pub struct Mnemonic {
	indices: [u16; MAX_WORDS],
	count: WordCount,
}

impl Mnemonic {
	/// Generates a mnemonic with fresh entropy.
	///
	/// # Errors
	///
	/// Returns [`Error::Entropy`] if the entropy source fails.
	pub fn generate(count: WordCount, entropy: &mut impl Entropy) -> Result<Self, Error> {
		let mut bytes = Secret::<32>::zeroed();
		let buf = bytes.expose_mut().get_mut(..count.entropy_len()).ok_or(Error::InvalidLength)?;
		entropy.fill(buf)?;
		Self::from_entropy(buf)
	}

	/// Builds the mnemonic encoding `entropy`.
	///
	/// # Errors
	///
	/// Returns [`Error::InvalidLength`] unless `entropy` is 16, 20, 24, 28, or 32 bytes.
	pub fn from_entropy(entropy: &[u8]) -> Result<Self, Error> {
		let count = WordCount::from_entropy_len(entropy.len())?;
		let mut data = Secret::<33>::zeroed();
		let (head, tail) =
			data.expose_mut().split_at_mut_checked(entropy.len()).ok_or(Error::InvalidLength)?;
		head.copy_from_slice(entropy);
		*tail.first_mut().ok_or(Error::InvalidLength)? = checksum(entropy)?;

		let mut mnemonic = Self { indices: [0; MAX_WORDS], count };
		let used = entropy.len().checked_add(1).ok_or(Error::InvalidLength)?;
		unpack(data.expose().get(..used).ok_or(Error::InvalidLength)?, mnemonic.used_mut())?;
		Ok(mnemonic)
	}

	/// Parses a mnemonic of English words separated by ASCII whitespace.
	///
	/// Words must match the wordlist exactly; abbreviations are rejected.
	///
	/// # Errors
	///
	/// Returns [`Error::InvalidLength`] for an unsupported word count, [`Error::InvalidEncoding`]
	/// for a word outside the wordlist, and [`Error::InvalidChecksum`] for a checksum mismatch.
	pub fn parse(phrase: &str) -> Result<Self, Error> {
		let mut mnemonic = Self { indices: [0; MAX_WORDS], count: WordCount::W24 };
		let mut words = 0usize;
		for word in phrase.split_ascii_whitespace() {
			let slot = mnemonic.indices.get_mut(words).ok_or(Error::InvalidLength)?;
			*slot = index_of(word).ok_or(Error::InvalidEncoding)?;
			words = words.checked_add(1).ok_or(Error::InvalidLength)?;
		}
		mnemonic.count = WordCount::from_words(words)?;

		let mut data = Secret::<33>::zeroed();
		pack(mnemonic.used(), data.expose_mut())?;
		let (entropy, tail) = data
			.expose()
			.split_at_checked(mnemonic.count.entropy_len())
			.ok_or(Error::InvalidLength)?;
		let stored = tail.first().ok_or(Error::InvalidLength)?;
		let mask = u8::MAX
			.checked_shl(
				8u32.checked_sub(mnemonic.count.checksum_bits()).ok_or(Error::InvalidLength)?,
			)
			.ok_or(Error::InvalidLength)?;
		if (checksum(entropy)? ^ stored) & mask != 0 {
			return Err(Error::InvalidChecksum);
		}
		Ok(mnemonic)
	}

	/// Number of words.
	pub const fn word_count(&self) -> WordCount {
		self.count
	}

	/// Words of the mnemonic, in order.
	pub fn words(&self) -> impl Iterator<Item = &'static str> + '_ {
		self.used().iter().filter_map(|&index| word(index))
	}

	/// Derives the BIP-39 seed.
	///
	/// Without the `nfkd` feature, the passphrase must be ASCII. With it, the passphrase is NFKD
	/// normalized.
	///
	/// # Errors
	///
	/// Returns [`Error::Unsupported`] for a non-ASCII passphrase without `nfkd`, and
	/// [`Error::LimitExceeded`] if the passphrase exceeds [`MAX_PASSPHRASE_LEN`] after
	/// normalization.
	pub fn to_seed(&self, passphrase: &str) -> Result<Seed, Error> {
		let mut sentence = Secret::<MAX_SENTENCE_LEN>::zeroed();
		let mut sentence_len = 0;
		for (i, word) in self.words().enumerate() {
			if i > 0 {
				put(sentence.expose_mut(), &mut sentence_len, b" ")?;
			}
			put(sentence.expose_mut(), &mut sentence_len, word.as_bytes())?;
		}

		let mut salt = Secret::<SALT_CAPACITY>::zeroed();
		let mut salt_len = 0;
		put(salt.expose_mut(), &mut salt_len, SALT_PREFIX)?;
		put_passphrase(salt.expose_mut(), &mut salt_len, passphrase)?;

		let mut seed = Seed::zeroed();
		pbkdf2::pbkdf2::<Hmac<Sha512>>(
			sentence.expose().get(..sentence_len).ok_or(Error::InvalidLength)?,
			salt.expose().get(..salt_len).ok_or(Error::InvalidLength)?,
			ROUNDS,
			seed.expose_mut(),
		)
		.map_err(|_| Error::InvalidLength)?;
		Ok(seed)
	}

	fn used(&self) -> &[u16] {
		self.indices.get(..self.count.words()).unwrap_or(&[])
	}

	fn used_mut(&mut self) -> &mut [u16] {
		self.indices.get_mut(..self.count.words()).unwrap_or(&mut [])
	}
}

impl Drop for Mnemonic {
	fn drop(&mut self) {
		self.indices.zeroize();
	}
}

impl fmt::Debug for Mnemonic {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("Mnemonic([REDACTED])")
	}
}

fn word(index: u16) -> Option<&'static str> {
	WORDLIST.lines().nth(usize::from(index))
}

fn index_of(word: &str) -> Option<u16> {
	WORDLIST.lines().position(|w| w == word).and_then(|i| u16::try_from(i).ok())
}

fn checksum(entropy: &[u8]) -> Result<u8, Error> {
	Sha256::digest(entropy).first().copied().ok_or(Error::InvalidLength)
}

fn unpack(data: &[u8], out: &mut [u16]) -> Result<(), Error> {
	let mut acc: u32 = 0;
	let mut bits: u32 = 0;
	let mut slots = out.iter_mut();
	for &byte in data {
		acc = acc.checked_shl(8).ok_or(Error::InvalidLength)? | u32::from(byte);
		bits = bits.checked_add(8).ok_or(Error::InvalidLength)?;
		if let Some(rest) = bits.checked_sub(11) {
			let Some(slot) = slots.next() else {
				return Ok(());
			};
			let index = acc.checked_shr(rest).ok_or(Error::InvalidLength)? & 0x7ff;
			*slot = u16::try_from(index).map_err(|_| Error::InvalidLength)?;
			acc &= !u32::MAX.checked_shl(rest).ok_or(Error::InvalidLength)?;
			bits = rest;
		}
	}
	Ok(())
}

fn pack(indices: &[u16], out: &mut [u8]) -> Result<(), Error> {
	let mut acc: u32 = 0;
	let mut bits: u32 = 0;
	let mut slots = out.iter_mut();
	for &index in indices {
		acc = acc.checked_shl(11).ok_or(Error::InvalidLength)? | u32::from(index);
		bits = bits.checked_add(11).ok_or(Error::InvalidLength)?;
		while let Some(rest) = bits.checked_sub(8) {
			let byte = acc.checked_shr(rest).ok_or(Error::InvalidLength)? & 0xff;
			*slots.next().ok_or(Error::InvalidLength)? =
				u8::try_from(byte).map_err(|_| Error::InvalidLength)?;
			acc &= !u32::MAX.checked_shl(rest).ok_or(Error::InvalidLength)?;
			bits = rest;
		}
	}
	if bits > 0 {
		let shift = 8u32.checked_sub(bits).ok_or(Error::InvalidLength)?;
		let byte = acc.checked_shl(shift).ok_or(Error::InvalidLength)?;
		*slots.next().ok_or(Error::InvalidLength)? =
			u8::try_from(byte).map_err(|_| Error::InvalidLength)?;
	}
	Ok(())
}

fn put(buf: &mut [u8], len: &mut usize, bytes: &[u8]) -> Result<(), Error> {
	let end = len.checked_add(bytes.len()).ok_or(Error::LimitExceeded)?;
	buf.get_mut(*len..end).ok_or(Error::LimitExceeded)?.copy_from_slice(bytes);
	*len = end;
	Ok(())
}

#[cfg(feature = "nfkd")]
fn put_passphrase(buf: &mut [u8], len: &mut usize, passphrase: &str) -> Result<(), Error> {
	let mut chars = Zeroizing::new(['\0'; MAX_PASSPHRASE_LEN]);
	let mut free = chars.iter_mut();
	let mut overflow = false;
	for c in passphrase.chars() {
		decompose_compatible(c, |d| match free.next() {
			Some(slot) => *slot = d,
			None => overflow = true,
		});
		if overflow {
			return Err(Error::LimitExceeded);
		}
	}
	let count = MAX_PASSPHRASE_LEN.checked_sub(free.len()).ok_or(Error::LimitExceeded)?;
	let used = chars.get_mut(..count).ok_or(Error::LimitExceeded)?;
	reorder(used);
	let mut utf8 = [0u8; 4];
	for c in used.iter() {
		let result = put(buf, len, c.encode_utf8(&mut utf8).as_bytes());
		utf8.zeroize();
		result?;
	}
	Ok(())
}

#[cfg(feature = "nfkd")]
fn reorder(chars: &mut [char]) {
	let mut swapped = true;
	while swapped {
		swapped = false;
		for start in 0..chars.len() {
			if let Some([a, b]) = chars.get_mut(start..).and_then(<[char]>::first_chunk_mut::<2>) {
				let class = canonical_combining_class(*b);
				if class != 0 && canonical_combining_class(*a) > class {
					core::mem::swap(a, b);
					swapped = true;
				}
			}
		}
	}
}

#[cfg(not(feature = "nfkd"))]
fn put_passphrase(buf: &mut [u8], len: &mut usize, passphrase: &str) -> Result<(), Error> {
	if !passphrase.is_ascii() {
		return Err(Error::Unsupported);
	}
	put(buf, len, passphrase.as_bytes())
}

#[cfg(all(test, feature = "nfkd"))]
mod tests {
	extern crate alloc;

	use alloc::{string::String, vec::Vec};

	use unicode_normalization::{UnicodeNormalization, char::canonical_combining_class};

	use super::{Error, MAX_PASSPHRASE_LEN, SALT_CAPACITY, SALT_PREFIX, put_passphrase};

	fn check(passphrase: &str) {
		let expected: String = passphrase.nfkd().collect();
		let mut buf = [0u8; SALT_CAPACITY];
		let mut len = SALT_PREFIX.len();
		let result = put_passphrase(&mut buf, &mut len, passphrase);
		if expected.len() <= MAX_PASSPHRASE_LEN {
			assert_eq!(result, Ok(()), "{passphrase:?}");
			assert_eq!(
				buf.get(SALT_PREFIX.len()..len),
				Some(expected.as_bytes()),
				"{passphrase:?}"
			);
		} else {
			assert_eq!(result, Err(Error::LimitExceeded), "{passphrase:?}");
		}
	}

	#[test]
	fn every_char_matches_nfkd() {
		let mut utf8 = [0u8; 4];
		for c in (0..=0x10_ffff).filter_map(char::from_u32) {
			check(c.encode_utf8(&mut utf8));
		}
	}

	#[test]
	fn combining_sequences_match_nfkd() {
		let mut pool: Vec<char> = (0..=0x10_ffff)
			.filter_map(char::from_u32)
			.filter(|&c| canonical_combining_class(c) != 0)
			.collect();
		pool.extend([
			'a', 'e', ' ', '\u{344}', '\u{f73}', '\u{1e0b}', '\u{1100}', '\u{ac00}', '\u{fb2c}',
			'\u{fdfa}',
		]);
		let mut state = 0x9e37_79b9_7f4a_7c15_u64;
		let mut next = |bound: usize| {
			state ^= state << 13;
			state ^= state >> 7;
			state ^= state << 17;
			usize::try_from(state).unwrap_or(0).checked_rem(bound).unwrap_or(0)
		};
		for _ in 0..20_000 {
			let len = next(40);
			let passphrase: String =
				(0..len).filter_map(|_| pool.get(next(pool.len())).copied()).collect();
			check(&passphrase);
		}
	}
}
