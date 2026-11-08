# sigroot

A modular Rust wallet core for offline signing and multichain self-custody.

> **Status: pre-alpha.** Not implemented, not audited, not for use with real assets.

## Vision

sigroot is a minimal Rust library for building secure cryptocurrency wallets. Its purpose is to provide a small, understandable, and verifiable foundation for key management, address handling, transaction authorization, and offline signing.

The first practical use case is a personal wallet application running on a dedicated, hardened computer. The library should also be useful to independent developers building desktop wallets, cold-wallet tools, hardware signers, and other security-sensitive applications.

Today nothing can be trusted by default: not dependencies, not toolchains, not build pipelines, not hosts, and not the code itself. The only realistic path to something truly secure is radical minimalism, simplicity, and strong verification on many independent levels. Every line of code, every dependency, and every feature must justify its existence, and every claim must be backed by evidence for the exact operation and configuration it covers.

## Principles

- **Nothing is on by default.** Every capability is opted into by name.
- **You pay only for what you enable.** Each capability pulls in only the code and dependencies it needs.
- **`no_std` and size are priorities.** See below.
- **No runtime baggage.** No network, filesystem, database, UI, async runtime, or global state. The host supplies entropy, storage, transport, and display.
- **Established cryptography only.** sigroot composes reviewed implementations; it does not implement its own primitives.
- **Refuse rather than guess.** Unsupported profiles, networks, or transaction types are errors, never a silent fallback.

## `no_std` and size

Every crate is unconditionally `#![no_std]`. All functionality works without an allocator; `alloc` and `std` only add conveniences on top.

- Fixed-size types for keys, signatures, and addresses.
- Decoding borrows from the input; encoding writes into a caller-provided buffer; hashing is streamed.
- Inputs have explicit size limits.
- Errors implement `core::error::Error`.
- Dependencies are used with `default-features = false`.

CI builds every non-`alloc` feature for a bare-metal target and links a minimal binary without a global allocator. Code size of each feature is measured and tracked.

## Crates

| Crate | Responsibility |
| --- | --- |
| `sigroot-core` | Error types, secret containers (redacted `Debug`, zeroize on drop, no `Serialize`), fallible `Entropy` trait. |
| `sigroot-hd` | BIP-39 mnemonics and BIP-32 secp256k1 derivation. |
| `sigroot-eth` | Ethereum: addresses, keys, signing payloads, transactions, interpretation, policy. |

Cargo features are unified across the dependency graph, so they are used to reduce what gets compiled, never as a security boundary. Check the effective feature set with `cargo tree -e features`.

## Ethereum

### Layers

Each layer depends only on the layers below it.

```text
L5  policy
L4  erc20
L3  eip191   tx-legacy   tx-eip2930   tx-eip1559
L2  keys  ──  hd  ──  mnemonic
L1  pubkey   verify
L0  address
    (always)  Signer trait, ChainId, errors
```

### Features of `sigroot-eth`

| Feature | Provides | Implies |
| --- | --- | --- |
| *(none)* | `Signer` trait, `ChainId`, errors. | |
| `address` | `Address`, EIP-55 encode, parse, validate. | |
| `pubkey` | secp256k1 public keys, address derivation. | `address` |
| `verify` | Signature parsing, low-`s` enforcement, recovery, verification. | `pubkey` |
| `keys` | In-memory `SigningKey` implementing `Signer`. | `pubkey` |
| `hd` | Derivation according to a wallet profile. | `keys` |
| `mnemonic` | BIP-39 generation and import. | `hd` |
| `eip191` | `personal_sign` payloads. | |
| `tx-legacy` | Legacy transactions, EIP-155 only. | |
| `tx-eip2930` | Type 1 transactions. | |
| `tx-eip1559` | Type 2 transactions. | |
| `erc20` | Interpretation of `transfer`, `transferFrom`, `approve`. | |
| `policy` | Chain ID, recipient, value, fee, and contract-call rules checked before signing. | |
| `unchecked-prehash` | `sign_prehash` over a raw 32-byte digest. Bypasses interpretation and policy. | `keys` |
| `alloc` | Owned convenience types, Unicode passphrase normalization. | |
| `std` | `OsEntropy` backed by the operating system. | `alloc` |

Each `tx-*` feature encodes, decodes, hashes, and assembles signed transactions.

### Signing

`Signer` accepts only typed payloads, never raw bytes. Each payload type carries its own domain, so a transaction cannot be signed as a message or the other way around. External and hardware signers implement the same trait; the private key never has to leave them.

### Wallet profile `eth-bip44-v1`

| Parameter | Value |
| --- | --- |
| Mnemonic | BIP-39, English, 24 words, optional passphrase (ASCII only without `alloc`) |
| Derivation | BIP-32, secp256k1 |
| Path | `m/44'/60'/0'/0/{index}` |
| Address | Keccak-256 of the uncompressed public key, last 20 bytes, EIP-55 |
| Network | Explicit chain ID on every signing operation, no default |

### Composition by role

```toml
# Watch-only
sigroot-eth = { version = "0.1", default-features = false, features = ["address"] }

# Online coordinator
sigroot-eth = { version = "0.1", default-features = false, features = ["tx-eip1559", "verify"] }

# Offline signer
sigroot-eth = { version = "0.1", default-features = false, features = ["mnemonic", "tx-eip1559", "erc20", "policy"] }

# External signer integration
sigroot-eth = { version = "0.1", default-features = false, features = ["tx-eip1559", "policy"] }
```

## Development

```sh
cargo install --locked taplo-cli --version 0.10.0
lefthook install
```

## License

[MIT](LICENSE). Copyright (c) 2026 aletheia-labs.
