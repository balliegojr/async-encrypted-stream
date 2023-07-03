use std::error::Error;

use chacha20poly1305::aead::stream::{DecryptorLE31, EncryptorLE31};
use chacha20poly1305::XChaCha20Poly1305;

use async_encrypted_stream::{encrypted_stream, ReadHalf, WriteHalf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn test_tcp_stream() -> Result<(), Box<dyn Error>> {
    let port = echo_server().await?;

    let (rx, tx) = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await?
        .into_split();

    let mut buf = [0u8; 128];
    let (mut read, mut write) = get_stream(rx, tx);
    write.write_all(b"ping").await?;

    let read_bytes = read.read(&mut buf).await?;
    assert_eq!(buf[..read_bytes], b"ping"[..]);

    write.write_all(b"pong").await?;

    let read_bytes = read.read(&mut buf).await?;
    assert_eq!(buf[..read_bytes], b"pong"[..]);

    Ok(())
}

fn get_stream(
    rx: tokio::net::tcp::OwnedReadHalf,
    tx: tokio::net::tcp::OwnedWriteHalf,
) -> (
    ReadHalf<tokio::net::tcp::OwnedReadHalf, DecryptorLE31<XChaCha20Poly1305>>,
    WriteHalf<tokio::net::tcp::OwnedWriteHalf, EncryptorLE31<XChaCha20Poly1305>>,
) {
    // The key and nonce used must be the same on both ends of the stream
    let key = [0u8; 32];
    let nonce = [0u8; 20];

    encrypted_stream(rx, tx, key.as_ref().into(), nonce.as_ref().into())
}

async fn echo_server() -> Result<u16, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (rx, tx) = stream.into_split();
            let (mut read, mut write) = get_stream(rx, tx);

            let mut buf = [0u8; 128];
            while let Ok(read) = read.read(&mut buf).await {
                let _ = write.write_all(&buf[..read]).await;
                let _ = write.flush().await;
            }
        }
    });

    Ok(port)
}
