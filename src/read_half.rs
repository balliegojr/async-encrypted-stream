use chacha20poly1305::{
    aead::{
        generic_array::ArrayLength,
        stream::{Decryptor, NonceSize, StreamPrimitive},
    },
    AeadInPlace,
};
use pin_project_lite::pin_project;
use std::{ops::Sub, pin::Pin, task::ready};

use tokio::io::{AsyncBufRead, AsyncRead};

use crate::DEFAULT_BUFFER_SIZE;

pin_project! {
    /// Async Encryption Read Half
    pub struct ReadHalf<T, U> {

        #[pin]
        inner: T,
        decryptor: U,
        buffer: Vec<u8>,
        pos: usize,
        cap: usize
    }
}

impl<T, A, S> ReadHalf<T, Decryptor<A, S>>
where
    S: StreamPrimitive<A>,
    A: AeadInPlace,
    A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    pub fn new(inner: T, decryptor: Decryptor<A, S>) -> Self {
        Self::with_capacity(inner, decryptor, DEFAULT_BUFFER_SIZE)
    }
    pub fn with_capacity(inner: T, decryptor: Decryptor<A, S>, size: usize) -> Self {
        Self {
            inner,
            decryptor,
            buffer: vec![0u8; size],
            pos: 0,
            cap: 0,
        }
    }

    /// Produce a value if there is enough data in the internal buffer
    ///
    /// When a value is produced, it will advance the buffer to the position for the next value.
    fn produce(mut self: Pin<&mut Self>) -> std::io::Result<Option<Vec<u8>>> {
        if self.cap <= self.pos {
            return Ok(None);
        }

        // Producing a value is a relatively simple operation.
        // Read 4 bytes from the buffer and cast to a u32 as the length of the message.
        // If there is enough bytes in the buffer, read the bytes and decrypt the message.
        //
        // Then advance the buffer to the next position (4 + length)
        //
        // If there isn't enough bytes to produce a message, just return None

        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&self.buffer[self.pos..self.pos + 4]);
        let length = u32::from_le_bytes(length_bytes) as usize;

        let me = self.as_mut().project();
        if *me.cap >= *me.pos + length + 4 {
            let decrypted = me
                .decryptor
                .decrypt_next(&me.buffer[*me.pos + 4..*me.pos + 4 + length])
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;

            *me.pos += 4 + length;
            if *me.pos == *me.cap {
                *me.pos = 0;
                *me.cap = 0;
            }

            Ok(Some(decrypted))
        } else {
            self.adjust_buffer(length + 4);
            Ok(None)
        }
    }

    /// Adjusts the buffer to fit the next full message.
    ///
    /// When the buffer reach a position where the length of the message is greater than the buffer
    /// available capacity, it is necessary to reset the buffer position to 0 and move the bytes
    /// available to the beginning of the buffer, freeing buffer capacity to be filled.
    ///
    /// It is also possible that the message length is bigger than the buffer full size, in this
    /// case the buffer will be resized to double it's full capacity. This operation should not
    /// be necessary because the writter is limited to write 1024 bytes long messages
    fn adjust_buffer(self: Pin<&mut Self>, desired_additional: usize) {
        let me = self.project();
        if *me.cap + desired_additional >= me.buffer.len() && *me.pos > 0 {
            me.buffer.copy_within(*me.pos..*me.cap, 0);
            *me.cap -= *me.pos;
            *me.pos = 0;
        }

        if *me.pos + desired_additional > me.buffer.len() {
            me.buffer.resize(me.buffer.len() * 2, 0);
        }
    }

    /// Return the contents of the internal buffer at the current position, for diagnostic
    /// purposes.
    ///
    /// For each message available in the buffer, the first 4 bytes are the message length encoded
    /// as a **little endian** u32. The end of the buffer may contain incomplete data.
    pub fn buffer(&self) -> &[u8] {
        &self.buffer[self.pos..]
    }
}

impl<T, A, S> AsyncRead for ReadHalf<T, Decryptor<A, S>>
where
    T: AsyncRead,
    S: StreamPrimitive<A>,
    A: AeadInPlace,
    A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    /// The poll read simply tries to produce a value from the internal buffer.
    /// If no value is produced, it then tries to poll more bytes from the inner reader
    ///
    /// This function may return a [std::io::ErrorKind::InvalidData] if it is not possible to decrypt
    /// the message, in this case, further read attempts will always produce the same error.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            if let Some(decrypted) = self.as_mut().produce()? {
                if decrypted.len() > buf.remaining() {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::OutOfMemory,
                        "Decrypted value exceeds buffer capacity",
                    ))?;
                }

                buf.put_slice(&decrypted);
                return std::task::Poll::Ready(Ok(()));
            }

            if ready!(self.as_mut().poll_fill_buf(cx))?.is_empty() {
                return std::task::Poll::Ready(Ok(()));
            }
        }
    }
}

impl<R: AsyncRead, A, S> tokio::io::AsyncBufRead for ReadHalf<R, Decryptor<A, S>>
where
    S: StreamPrimitive<A>,
    A: AeadInPlace,
    A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    fn poll_fill_buf(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<&[u8]>> {
        let me = self.project();

        let mut buf = tokio::io::ReadBuf::new(&mut me.buffer[*me.cap..]);
        ready!(me.inner.poll_read(cx, &mut buf))?;
        if !buf.filled().is_empty() {
            *me.cap += buf.filled().len();
        }

        std::task::Poll::Ready(Ok(&me.buffer[*me.pos..*me.cap]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let me = self.project();
        *me.pos += amt;
        if *me.pos >= *me.cap {
            *me.pos = 0;
            *me.cap = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{assert_eq, time::Duration};

    use chacha20poly1305::{aead::stream::EncryptorLE31, KeyInit, XChaCha20Poly1305};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::get_key;

    use super::*;

    #[tokio::test]
    pub async fn test_crypto_stream_read_half() {
        let key: [u8; 32] = get_key("key", "group");
        let start_nonce = [0u8; 20];

        let (rx, mut tx) = tokio::io::duplex(100);

        tokio::spawn(async move {
            let encrypted_content = {
                let mut encryptor: EncryptorLE31<XChaCha20Poly1305> =
                    chacha20poly1305::aead::stream::EncryptorLE31::from_aead(
                        XChaCha20Poly1305::new(key.as_ref().into()),
                        start_nonce.as_ref().into(),
                    );

                let mut expected = Vec::new();

                for data in ["some content", "some other content", "even more content"] {
                    let mut encrypted = encryptor.encrypt_next(data.as_bytes()).unwrap();
                    expected.extend((encrypted.len() as u32).to_le_bytes());
                    expected.append(&mut encrypted);
                }

                expected
            };

            for chunk in encrypted_content.chunks(10) {
                let _ = tx.write(chunk).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });

        tokio::time::sleep(Duration::from_millis(20)).await;

        let decryptor = chacha20poly1305::aead::stream::DecryptorLE31::from_aead(
            XChaCha20Poly1305::new(key.as_ref().into()),
            start_nonce.as_ref().into(),
        );
        let mut reader = ReadHalf::new(rx, decryptor);

        let mut plain_content = String::new();
        let _ = reader.read_to_string(&mut plain_content).await;

        assert_eq!(
            plain_content,
            "some contentsome other contenteven more content"
        );
    }

    #[tokio::test]
    pub async fn test_read_invalid_data() {
        let key: [u8; 32] = get_key("key", "group");
        let start_nonce = [0u8; 20];

        let (rx, _tx) = tokio::io::duplex(100);

        let decryptor = chacha20poly1305::aead::stream::DecryptorLE31::from_aead(
            XChaCha20Poly1305::new(key.as_ref().into()),
            start_nonce.as_ref().into(),
        );
        let mut reader = ReadHalf::new(rx, decryptor);
        let mut reader_data = Vec::from_iter(10u32.to_le_bytes());
        reader_data.extend_from_slice(&[0u8; 20]);

        reader.cap = reader_data.len();
        reader.buffer = reader_data;

        let mut buf = [0u8; 1024];

        assert!(reader.read(&mut buf).await.is_err());
        assert!(reader.read(&mut buf).await.is_err());
    }
}
