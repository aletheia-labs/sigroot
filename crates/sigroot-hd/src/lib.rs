//! BIP-39 mnemonics and BIP-32 secp256k1 derivation for sigroot.

#![no_std]

#[cfg(feature = "bip32")]
mod bip32;
#[cfg(feature = "bip39")]
mod bip39;

#[cfg(feature = "bip32")]
pub use bip32::{DerivationPath, ExtendedPrivateKey, HARDENED, MAX_DEPTH};
#[cfg(feature = "bip39")]
pub use bip39::{MAX_PASSPHRASE_LEN, Mnemonic, WordCount};
pub use sigroot_core::{Entropy, Error, Secret};

/// BIP-39 seed.
pub type Seed = Secret<64>;
