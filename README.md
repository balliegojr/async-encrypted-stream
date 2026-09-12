# Async Encrypted Stream


[![Rust](https://github.com/balliegojr/async-encrypted-stream/actions/workflows/rust.yml/badge.svg)](https://github.com/balliegojr/async-encrypted-stream/actions/workflows/rust.yml)
[![dependency status](https://deps.rs/repo/github/balliegojr/async-encrypted-stream/status.svg)](https://deps.rs/repo/github/balliegojr/async-encrypted-stream)


Async Read and Write wrappers around the chacha20 encryption primitives.

This crate exposes a pair of [ReadHalf] and [WriteHalf] structs that works with any [tokio::io::AsyncRead] and [tokio::io::AsyncWrite] respectively.

To use this crate, it is necessary to add [chacha20poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) as a dependency as well.

```Cargo.toml
async-encrypted-stream = "0.2"
```

Once the necessary dependencies are added, creating the stream is fairly trivial

```rust
use async_encrypted_stream::aead_stream::{DecryptorLE31, EncryptorLE31};
use async_encrypted_stream::chacha20poly1305::XChaCha20Poly1305;
use async_encrypted_stream::{ReadHalf, WriteHalf, encrypted_stream};

// The key and nonce used must be the same on both ends of the stream
// NOTE: the size of the key and nonce values are defined by the type of Encryption used
let key = [0u8; 32];
let nonce = [0u8; 20];

let (rx, tx) = tokio::io::duplex(4096);
let (mut reader, mut writer): (
    ReadHalf<_, DecryptorLE31<XChaCha20Poly1305>>,
    WriteHalf<_, EncryptorLE31<XChaCha20Poly1305>>,
) = encrypted_stream(rx, tx, (&key).into(), (&nonce).into());
```
