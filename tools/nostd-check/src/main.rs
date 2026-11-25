#![cfg_attr(target_os = "none", no_std, no_main)]

use core::hint::black_box;

use sigroot_core as _;

#[cfg(not(any(feature = "address", feature = "offline", feature = "full")))]
compile_error!("enable one size profile: address, offline, or full");

#[cfg(feature = "full")]
fn run() -> Result<usize, sigroot_eth::Error> {
	use sigroot_eth::{
		AccessList, Address, Calls, ChainId, Eip1559Tx, Eip2930Tx, Erc20Call, Error, LegacyTx,
		Payload, PersonalMessage, Policy, Signer, U256, UncheckedPrehash, hd,
	};

	const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
		abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
		abandon art";

	let mnemonic = hd::Mnemonic::parse(black_box(PHRASE))?;
	let key = hd::derive_from_mnemonic(&mnemonic, black_box(""), black_box(0))?;
	let recipient = key.address();
	let token = Address::parse(black_box("0x6B175474E89094C44Da98b954EedeAC495271d0F"))?;
	let chain_id = ChainId::new(black_box(1))?;

	let mut input = [0; 68];
	Erc20Call::Transfer { to: recipient, amount: U256::from(black_box(1_u64)) }
		.encode(&mut input)?;
	let tx = Eip1559Tx {
		chain_id,
		nonce: black_box(0),
		max_priority_fee_per_gas: black_box(1),
		max_fee_per_gas: black_box(10),
		gas_limit: black_box(65_000),
		to: Some(token),
		value: U256::ZERO,
		input: &input,
		access_list: AccessList::from_rlp(black_box(&[0xc0]))?,
	};
	let chains = [chain_id];
	let recipients = [recipient];
	let tokens = [token];
	let policy = Policy {
		chain_ids: &chains,
		recipients: Some(&recipients),
		max_value: Some(U256::from(black_box(0_u64))),
		max_fee: Some(black_box(1_000_000)),
		calls: Calls::Erc20 { tokens: &tokens, allow_approve: false },
	};
	policy.check(&tx).map_err(|_| Error::Unsupported)?;

	let signature = key.sign(Payload::Eip1559(&tx))?;
	let mut buf = [0; 256];
	let len = tx.encode_signed(&signature, &mut buf)?;
	let (decoded, signature) =
		Eip1559Tx::decode_signed(black_box(buf.get(..len).ok_or(Error::BufferTooSmall)?))?;
	key.public_key().verify(Payload::Eip1559(&decoded), &signature)?;

	let legacy = LegacyTx {
		chain_id,
		nonce: black_box(1),
		gas_price: black_box(1),
		gas_limit: black_box(21_000),
		to: Some(recipient),
		value: U256::from(black_box(1_u64)),
		input: &[],
	};
	let signature = key.sign(Payload::Legacy(&legacy))?;
	let len = legacy.encode_signed(&signature, &mut buf)?;
	LegacyTx::decode_signed(black_box(buf.get(..len).ok_or(Error::BufferTooSmall)?))?;

	let eip2930 = Eip2930Tx {
		chain_id,
		nonce: black_box(2),
		gas_price: black_box(1),
		gas_limit: black_box(21_000),
		to: Some(recipient),
		value: U256::ZERO,
		input: &[],
		access_list: AccessList::EMPTY,
	};
	let signature = key.sign(Payload::Eip2930(&eip2930))?;
	let len = eip2930.encode_signed(&signature, &mut buf)?;
	Eip2930Tx::decode_signed(black_box(buf.get(..len).ok_or(Error::BufferTooSmall)?))?;

	let message = PersonalMessage::new(black_box(b"sigroot"));
	let signature = key.sign(Payload::PersonalMessage(&message))?;
	signature.recover(Payload::PersonalMessage(&message))?;
	key.sign(Payload::UncheckedPrehash(&UncheckedPrehash(black_box([1; 32]))))?;

	Ok(black_box(len))
}

#[cfg(all(feature = "offline", not(feature = "full")))]
fn run() -> Result<usize, sigroot_eth::Error> {
	use sigroot_eth::{
		AccessList, Address, Calls, ChainId, Eip1559Tx, Payload, Policy, Signer, U256, hd,
	};

	const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
		abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
		abandon art";

	let mnemonic = hd::Mnemonic::parse(black_box(PHRASE))?;
	let key = hd::derive_from_mnemonic(&mnemonic, black_box(""), black_box(0))?;
	let recipient = Address::parse(black_box("0x3535353535353535353535353535353535353535"))?;
	let chain_id = ChainId::new(black_box(1))?;
	let tx = Eip1559Tx {
		chain_id,
		nonce: black_box(0),
		max_priority_fee_per_gas: black_box(1_000_000_000),
		max_fee_per_gas: black_box(20_000_000_000),
		gas_limit: black_box(21_000),
		to: Some(recipient),
		value: U256::from(black_box(1_000_000_000_000_000_000_u128)),
		input: &[],
		access_list: AccessList::EMPTY,
	};
	let chains = [chain_id];
	let recipients = [recipient];
	let policy = Policy {
		chain_ids: &chains,
		recipients: Some(&recipients),
		max_value: Some(U256::from(black_box(2_000_000_000_000_000_000_u128))),
		max_fee: Some(black_box(500_000_000_000_000)),
		calls: Calls::Deny,
	};
	policy.check(&tx).map_err(|_| sigroot_eth::Error::Unsupported)?;

	let signature = key.sign(Payload::Eip1559(&tx))?;
	key.public_key().verify(Payload::Eip1559(&tx), &signature)?;
	let mut buf = [0; 256];
	let len = tx.encode_signed(&signature, &mut buf)?;
	let encoded = buf.get(..len).ok_or(sigroot_eth::Error::BufferTooSmall)?;
	Ok(black_box(encoded).len())
}

#[cfg(all(feature = "address", not(feature = "offline"), not(feature = "full")))]
fn run() -> Result<usize, sigroot_eth::Error> {
	use sigroot_eth::{Address, Error};

	let address = Address::parse(black_box("0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb"))?;
	Ok(black_box(usize::from(*address.as_bytes().first().ok_or(Error::InvalidLength)?)))
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
	#[allow(clippy::empty_loop)]
	loop {}
}

#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
	let _ = black_box(run());
	#[allow(clippy::empty_loop)]
	loop {}
}

#[cfg(not(target_os = "none"))]
fn main() {
	let _ = black_box(run());
}
