# Async Encrypted Stream

Async Read and Write wrappers around the chacha20 encryption primitives.

This crate exposes a pair of [ReadHalf] and [WriteHalf] structs that works with any [tokio::io::AsyncRead] and [tokio::io::AsyncWrite] respectively.

To use this crate, it is necessary to add [chacha20poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) as a dependency as well.

```Cargo.toml
async-encrypted-stream = "0.1"
chacha20poly1305 = { version = "0.10", features = ["stream"] }
```

Once the necessary dependencies are added, creating the stream is fairly trivial

```rust
use chacha20poly1305::aead::stream::{DecryptorLE31, EncryptorLE31};
use chacha20poly1305::XChaCha20Poly1305;

use async_encrypted_stream::{ReadHalf, WriteHalf, encrypted_stream};

// The key and nonce used must be the same on both ends of the stream
// NOTE: the size of the key and nonce values are defined by the type of Encryption used
let key = [0u8; 32];
let nonce = [0u8; 20];

let (rx, tx) = tokio::io::duplex(4096);
let (mut reader, mut writer): (
    ReadHalf<_, DecryptorLE31<XChaCha20Poly1305>>,
    WriteHalf<_, EncryptorLE31<XChaCha20Poly1305>>,
) = encrypted_stream(rx, tx, key.as_ref().into(), nonce.as_ref().into());
```
