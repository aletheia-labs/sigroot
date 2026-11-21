//! Wallet profile `eth-bip44-v1`: BIP-32 secp256k1 keys at `m/44'/60'/0'/0/{index}`.

pub use sigroot_hd::Seed;
use sigroot_hd::{DerivationPath, ExtendedPrivateKey, HARDENED};
#[cfg(feature = "mnemonic")]
pub use sigroot_hd::{Mnemonic, WordCount};

#[cfg(feature = "mnemonic")]
use crate::Entropy;
use crate::{Error, SigningKey};

/// Profile identifier.
pub const PROFILE: &str = "eth-bip44-v1";

/// Derives the key at `m/44'/60'/0'/0/{index}`.
///
/// # Errors
///
/// Returns [`Error::Unsupported`] for a hardened `index`, and [`Error::InvalidDerivation`] if the
/// seed produces no valid key.
pub fn derive(seed: &Seed, index: u32) -> Result<SigningKey, Error> {
	if index >= HARDENED {
		return Err(Error::Unsupported);
	}
	let path = DerivationPath::new(&[44 | HARDENED, 60 | HARDENED, HARDENED, 0, index])?;
	let key = ExtendedPrivateKey::from_seed(seed.expose())?.derive_path(&path)?;
	SigningKey::from_secret(key.private_key())
}

/// Generates a 24-word mnemonic.
///
/// # Errors
///
/// Returns [`Error::Entropy`] if the entropy source fails.
#[cfg(feature = "mnemonic")]
pub fn generate_mnemonic(entropy: &mut impl Entropy) -> Result<Mnemonic, Error> {
	Mnemonic::generate(WordCount::W24, entropy)
}

/// Derives the key at `m/44'/60'/0'/0/{index}` from a 24-word mnemonic.
///
/// # Errors
///
/// Returns [`Error::Unsupported`] for other word counts or a hardened `index`, and the errors
/// of [`Mnemonic::to_seed`].
#[cfg(feature = "mnemonic")]
pub fn derive_from_mnemonic(
	mnemonic: &Mnemonic,
	passphrase: &str,
	index: u32,
) -> Result<SigningKey, Error> {
	if mnemonic.word_count() != WordCount::W24 {
		return Err(Error::Unsupported);
	}
	derive(&mnemonic.to_seed(passphrase)?, index)
}
