//! Shared errors, secret containers, and entropy interface for sigroot.

#![no_std]

mod entropy;
mod error;
mod secret;

pub use entropy::Entropy;
#[cfg(feature = "std")]
pub use entropy::OsEntropy;
pub use error::Error;
pub use secret::Secret;
