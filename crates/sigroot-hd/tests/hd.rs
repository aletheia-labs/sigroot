//! BIP-39 and BIP-32 tests against unmodified upstream vectors.

use core::error::Error as StdError;

use sha2::{Digest, Sha256};
use sigroot_hd::{
	DerivationPath, Entropy, Error, ExtendedPrivateKey, HARDENED, MAX_PASSPHRASE_LEN, Mnemonic,
	WordCount,
};

type Result = core::result::Result<(), Box<dyn StdError>>;

fn hex(s: &str) -> core::result::Result<Vec<u8>, Box<dyn StdError>> {
	s.as_bytes()
		.chunks(2)
		.map(|pair| Ok(u8::from_str_radix(core::str::from_utf8(pair)?, 16)?))
		.collect()
}

fn phrase(mnemonic: &Mnemonic) -> String {
	mnemonic.words().collect::<Vec<_>>().join(" ")
}

struct Fixed<'a>(&'a [u8]);

impl Entropy for Fixed<'_> {
	fn fill(&mut self, dest: &mut [u8]) -> core::result::Result<(), Error> {
		dest.copy_from_slice(self.0.get(..dest.len()).ok_or(Error::Entropy)?);
		Ok(())
	}
}

struct Failing;

impl Entropy for Failing {
	fn fill(&mut self, _: &mut [u8]) -> core::result::Result<(), Error> {
		Err(Error::Entropy)
	}
}

#[test]
fn wordlist_is_sorted() {
	let list = include_str!("../src/english.txt");
	let words: Vec<_> = list.lines().collect();
	assert_eq!(words.len(), 2048);
	assert!(words.windows(2).all(|w| w.first() < w.last()));
}

const VECTORS_JSON: &str = include_str!("data/vectors.json");
const BIP32_SPEC: &str = include_str!("data/bip-0032.mediawiki");

fn sha256(data: &str) -> String {
	Sha256::digest(data.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn base58check(s: &str) -> core::result::Result<Vec<u8>, Box<dyn StdError>> {
	const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	let mut le = Vec::new();
	for c in s.bytes() {
		let mut carry = u32::try_from(ALPHABET.iter().position(|&a| a == c).ok_or("base58")?)?;
		for byte in &mut le {
			carry = u32::from(*byte)
				.checked_mul(58)
				.and_then(|v| v.checked_add(carry))
				.ok_or("base58")?;
			*byte = u8::try_from(carry & 0xff)?;
			carry = carry.checked_shr(8).ok_or("base58")?;
		}
		while carry > 0 {
			le.push(u8::try_from(carry & 0xff)?);
			carry = carry.checked_shr(8).ok_or("base58")?;
		}
	}
	le.extend(s.bytes().take_while(|&c| c == b'1').map(|_| 0));
	le.reverse();
	let (payload, checksum) = le.split_last_chunk::<4>().ok_or("base58")?;
	let digest = Sha256::digest(Sha256::digest(payload));
	if digest.get(..4) != Some(checksum.as_slice()) {
		return Err("base58 checksum".into());
	}
	Ok(payload.to_vec())
}

fn xprv(s: &str) -> core::result::Result<(Vec<u8>, Vec<u8>), Box<dyn StdError>> {
	let payload = base58check(s)?;
	let chain_code = payload.get(13..45).ok_or("xprv")?.to_vec();
	let key = payload.get(46..78).ok_or("xprv")?.to_vec();
	Ok((chain_code, key))
}

fn quoted(s: &str) -> Vec<&str> {
	s.split('"').skip(1).step_by(2).collect()
}

#[test]
fn sources_match_upstream() {
	assert_eq!(
		sha256(include_str!("../src/english.txt")),
		"2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
	);
	assert_eq!(
		sha256(VECTORS_JSON),
		"fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8"
	);
	assert_eq!(
		sha256(BIP32_SPEC),
		"e5e00a8289db2f681052cf24a745320afc225e66b25d1e489a7c884d2fc7f11f"
	);
}

#[test]
fn bip39_vectors() -> Result {
	let start = VECTORS_JSON.find("\"english\"").ok_or("english")?;
	let end = VECTORS_JSON.find("\"chinese_simplified\"").ok_or("end")?;
	let strings = quoted(VECTORS_JSON.get(start..end).ok_or("range")?);
	let (vectors, rest) = strings.get(1..).ok_or("empty")?.as_chunks::<4>();
	assert!(rest.is_empty());
	assert_eq!(vectors.len(), 24);
	for [entropy, words, seed, master] in vectors {
		let mnemonic = Mnemonic::from_entropy(&hex(entropy)?)?;
		assert_eq!(phrase(&mnemonic), *words);
		assert_eq!(phrase(&Mnemonic::parse(words)?), *words);

		let derived = mnemonic.to_seed("TREZOR")?;
		assert_eq!(derived.expose().as_slice(), hex(seed)?);

		let (chain_code, key) = xprv(master)?;
		let master = ExtendedPrivateKey::from_seed(derived.expose())?;
		assert_eq!(master.chain_code().expose().as_slice(), chain_code);
		assert_eq!(master.private_key().expose().as_slice(), key);
	}
	Ok(())
}

#[test]
fn bip32_vectors() -> Result {
	let end = BIP32_SPEC.find("===Test vector 5===").ok_or("vector 5")?;
	let mut seed = Vec::new();
	let mut path = String::new();
	let mut count = 0_usize;
	for line in BIP32_SPEC.get(..end).ok_or("range")?.lines() {
		if let Some(hex_seed) = line.strip_prefix("Seed (hex): ") {
			seed = hex(hex_seed)?;
		} else if let Some(chain) = line.strip_prefix("* Chain ") {
			path = chain.replace("<sub>H</sub>", "'");
		} else if let Some(encoded) = line.strip_prefix("** ext prv: ") {
			let (chain_code, key) = xprv(encoded)?;
			let child = ExtendedPrivateKey::from_seed(&seed)?
				.derive_path(&DerivationPath::parse(&path)?)?;
			assert_eq!(child.chain_code().expose().as_slice(), chain_code, "{path}");
			assert_eq!(child.private_key().expose().as_slice(), key, "{path}");
			count = count.checked_add(1).ok_or("overflow")?;
		}
	}
	assert_eq!(count, 17);
	Ok(())
}

#[test]
fn generate_uses_entropy() -> Result {
	let entropy = [0x7f; 32];
	let generated = Mnemonic::generate(WordCount::W24, &mut Fixed(&entropy))?;
	assert_eq!(phrase(&generated), phrase(&Mnemonic::from_entropy(&entropy)?));
	assert_eq!(generated.word_count(), WordCount::W24);
	assert_eq!(Mnemonic::generate(WordCount::W12, &mut Failing).err(), Some(Error::Entropy));
	Ok(())
}

#[test]
fn mnemonic_rejects_invalid_input() {
	let abandon = ["abandon"; 12].join(" ");
	assert_eq!(Mnemonic::parse(&abandon).err(), Some(Error::InvalidChecksum));
	assert_eq!(Mnemonic::parse(&["abandon"; 11].join(" ")).err(), Some(Error::InvalidLength));
	assert_eq!(Mnemonic::parse(&["abandon"; 25].join(" ")).err(), Some(Error::InvalidLength));
	assert_eq!(Mnemonic::parse("").err(), Some(Error::InvalidLength));
	let abbreviated = format!("{} abou", ["abandon"; 11].join(" "));
	assert_eq!(Mnemonic::parse(&abbreviated).err(), Some(Error::InvalidEncoding));
	let upper = format!("{} ABOUT", ["abandon"; 11].join(" "));
	assert_eq!(Mnemonic::parse(&upper).err(), Some(Error::InvalidEncoding));
	assert_eq!(Mnemonic::from_entropy(&[0; 15]).err(), Some(Error::InvalidLength));
	assert_eq!(Mnemonic::from_entropy(&[0; 33]).err(), Some(Error::InvalidLength));
}

#[test]
fn mnemonic_accepts_ascii_whitespace() -> Result {
	let canonical = format!("{} about", ["abandon"; 11].join(" "));
	let spaced = format!("  {}\n\tabout ", ["abandon"; 11].join("  "));
	assert_eq!(
		Mnemonic::parse(&spaced)?.to_seed("")?.expose(),
		Mnemonic::parse(&canonical)?.to_seed("")?.expose()
	);
	Ok(())
}

#[test]
fn passphrase_limits() -> Result {
	let mnemonic = Mnemonic::from_entropy(&[0; 16])?;
	assert!(mnemonic.to_seed(&"a".repeat(MAX_PASSPHRASE_LEN)).is_ok());
	assert_eq!(
		mnemonic.to_seed(&"a".repeat(MAX_PASSPHRASE_LEN + 1)).err(),
		Some(Error::LimitExceeded)
	);
	Ok(())
}

#[cfg(not(feature = "nfkd"))]
#[test]
fn non_ascii_passphrase_requires_nfkd() -> Result {
	let mnemonic = Mnemonic::from_entropy(&[0; 16])?;
	assert_eq!(mnemonic.to_seed("\u{e9}").err(), Some(Error::Unsupported));
	Ok(())
}

#[cfg(feature = "nfkd")]
#[test]
fn passphrase_is_nfkd_normalized() -> Result {
	let mnemonic = Mnemonic::from_entropy(&[0; 16])?;
	assert_eq!(mnemonic.to_seed("\u{e9}")?.expose(), mnemonic.to_seed("e\u{301}")?.expose());
	Ok(())
}

#[cfg(feature = "nfkd")]
#[test]
fn passphrase_limit_applies_after_normalization() -> Result {
	let mnemonic = Mnemonic::from_entropy(&[0; 16])?;
	let wide = "\u{1d400}".repeat(MAX_PASSPHRASE_LEN);
	assert_eq!(
		mnemonic.to_seed(&wide)?.expose(),
		mnemonic.to_seed(&"A".repeat(MAX_PASSPHRASE_LEN))?.expose()
	);
	assert_eq!(mnemonic.to_seed(&format!("{wide}A")).err(), Some(Error::LimitExceeded));
	let combining = format!("e{}", "\u{301}".repeat(100_000));
	assert_eq!(mnemonic.to_seed(&combining).err(), Some(Error::LimitExceeded));
	Ok(())
}

type Core<D> = <D as sha2::digest::block_api::CoreProxy>::Core;

#[test]
fn hash_states_zeroize_on_drop() {
	fn zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
	zeroize_on_drop::<sha2::Sha256>();
	zeroize_on_drop::<sha2::Sha512>();
	// `Hmac` has no marker of its own; its state is two of these cores and this buffer.
	zeroize_on_drop::<Core<sha2::Sha512>>();
	zeroize_on_drop::<sha2::digest::block_api::Buffer<Core<sha2::Sha512>>>();
}

#[test]
fn path_parsing() -> Result {
	assert_eq!(
		DerivationPath::parse("m/44'/60'/0'/0/7")?.as_slice(),
		[44 | HARDENED, 60 | HARDENED, HARDENED, 0, 7]
	);
	assert!(DerivationPath::parse("m")?.as_slice().is_empty());
	assert_eq!(DerivationPath::parse(&format!("m{}", "/0".repeat(16)))?.as_slice().len(), 16);
	assert_eq!(
		DerivationPath::parse(&format!("m{}", "/0".repeat(17))).err(),
		Some(Error::LimitExceeded)
	);
	for invalid in
		["", "M/0", "m/", "m//0", "m/01", "m/0h", "m/-1", "m/+1", "m/2147483648", "44'/0"]
	{
		assert_eq!(DerivationPath::parse(invalid).err(), Some(Error::InvalidEncoding), "{invalid}");
	}
	Ok(())
}

#[test]
fn seed_length_is_checked() {
	assert_eq!(ExtendedPrivateKey::from_seed(&[1; 15]).err(), Some(Error::InvalidLength));
	assert_eq!(ExtendedPrivateKey::from_seed(&[1; 65]).err(), Some(Error::InvalidLength));
	assert!(ExtendedPrivateKey::from_seed(&[1; 16]).is_ok());
}

#[test]
fn secrets_are_redacted() -> Result {
	let mnemonic = Mnemonic::from_entropy(&[0; 16])?;
	let master = ExtendedPrivateKey::from_seed(mnemonic.to_seed("")?.expose())?;
	assert_eq!(format!("{mnemonic:?}"), "Mnemonic([REDACTED])");
	assert_eq!(format!("{master:?}"), "ExtendedPrivateKey([REDACTED])");
	assert_eq!(format!("{:?}", master.private_key()), "Secret([REDACTED])");
	Ok(())
}
