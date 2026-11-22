//! Demonstrates the offline signing API with public test data.
//!
//! Flow: build an EIP-1559 transfer → check an explicit policy → sign →
//! verify → encode/decode round-trip.
//!
//! Uses the well-known 24-word BIP-39 test mnemonic of twenty-three `abandon`
//! words ending in `art` (Trezor crypto test vectors / BIP-39 corpus). The
//! passphrase is empty and the account index is `0`. These values are public
//! fixtures for demonstration only; this example is not a wallet and must not
//! be used with real funds or real secrets.

#![allow(missing_docs)]

use sigroot_eth::hd::{self, Mnemonic};
use sigroot_eth::{AccessList, Address, Calls, ChainId, Eip1559Tx, Payload, Policy, Signer, U256};

/// Public BIP-39 test mnemonic (24 words): 23× `abandon` + `art`.
const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

/// Account 0 at `m/44'/60'/0'/0/0` for [`TEST_MNEMONIC`] with an empty passphrase.
///
/// Published by [ZKNoxHQ/PQBIP39](https://github.com/ZKNoxHQ/PQBIP39) for this mnemonic and path
/// (checksummed here with EIP-55).
const EXPECTED_ADDRESS: &str = "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb";

fn main() -> Result<(), Box<dyn core::error::Error>> {
	let mnemonic = Mnemonic::parse(TEST_MNEMONIC)?;
	let key = hd::derive_from_mnemonic(&mnemonic, "", 0)?;
	let address = key.address();
	if address != Address::parse(EXPECTED_ADDRESS)? {
		return Err(format!("unexpected address {address}, expected {EXPECTED_ADDRESS}").into());
	}

	let chain_id = ChainId::new(1)?;
	let recipient = Address::parse("0x3535353535353535353535353535353535353535")?;
	let tx = Eip1559Tx {
		chain_id,
		nonce: 0,
		max_priority_fee_per_gas: 1_000_000_000,
		max_fee_per_gas: 20_000_000_000,
		gas_limit: 21_000,
		to: Some(recipient),
		value: U256::from(1_000_000_000_000_000_000_u128),
		input: &[],
		access_list: AccessList::EMPTY,
	};

	// Policy limits are chosen independently of the transaction fields above.
	let allowed_chains = [ChainId::new(1)?];
	let allowed_recipients = [Address::parse("0x3535353535353535353535353535353535353535")?];
	let policy = Policy {
		chain_ids: &allowed_chains,
		recipients: Some(&allowed_recipients),
		max_value: Some(U256::from(2_000_000_000_000_000_000_u128)),
		max_fee: Some(500_000_000_000_000),
		calls: Calls::Deny,
	};
	policy.check(&tx).map_err(|violation| format!("policy: {violation:?}"))?;

	let payload = Payload::Eip1559(&tx);
	let signature = key.sign(payload)?;
	key.public_key().verify(payload, &signature)?;

	let mut encoded = vec![0; tx.signed_len(&signature)?];
	let len = tx.encode_signed(&signature, &mut encoded)?;
	if len != encoded.len() {
		return Err(format!(
			"encode_signed wrote {len} bytes, signed_len predicted {}",
			encoded.len()
		)
		.into());
	}

	let (decoded_tx, decoded_signature) = Eip1559Tx::decode_signed(&encoded)?;
	if decoded_tx != tx || decoded_signature != signature {
		return Err("signed transaction round-trip mismatch".into());
	}

	println!("address\t{address}");
	println!("signed\t0x{}", Hex(&encoded));
	Ok(())
}

struct Hex<'a>(&'a [u8]);

impl core::fmt::Display for Hex<'_> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		for byte in self.0 {
			core::fmt::Write::write_fmt(f, format_args!("{byte:02x}"))?;
		}
		Ok(())
	}
}
