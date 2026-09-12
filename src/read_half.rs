use aead_stream::{Decryptor, NonceSize, StreamPrimitive};
use chacha20poly1305::aead::{array::ArraySize, AeadInOut};
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
        cap: usize,

        // Decrypted bytes from a message that didn't fully fit in the caller's read buffer,
        // waiting to be delivered on subsequent `poll_read` calls.
        overflow: Vec<u8>
    }
}

impl<T, A, S> ReadHalf<T, Decryptor<A, S>>
where
    S: StreamPrimitive<A>,
    A: AeadInOut,
    A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
    NonceSize<A, S>: ArraySize,
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
            overflow: Vec::new(),
        }
    }

    /// Produce a value if there is enough data in the internal buffer
    ///
    /// When a value is produced, it will advance the buffer to the position for the next value.
    fn produce(mut self: Pin<&mut Self>) -> std::io::Result<Option<Vec<u8>>> {
        if self.cap <= self.pos {
            return Ok(None);
        }

        if self.cap - self.pos < 4 {
            // Not enough bytes buffered yet to even read the length prefix.
            self.adjust_buffer(4);
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
    A: AeadInOut,
    A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
    NonceSize<A, S>: ArraySize,
{
    /// The poll read simply tries to produce a value from the internal buffer.
    /// If no value is produced, it then tries to poll more bytes from the inner reader
    ///
    /// If a decrypted message is larger than the caller's buffer, the remainder is held in an
    /// internal overflow buffer and delivered on subsequent calls, instead of being discarded.
    ///
    /// This function may return a [std::io::ErrorKind::InvalidData] if it is not possible to decrypt
    /// the message, in this case, further read attempts will always produce the same error.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            if !self.overflow.is_empty() {
                let me = self.as_mut().project();
                let n = std::cmp::min(me.overflow.len(), buf.remaining());
                buf.put_slice(&me.overflow[..n]);
                me.overflow.drain(..n);
                return std::task::Poll::Ready(Ok(()));
            }

            if let Some(decrypted) = self.as_mut().produce()? {
                let n = std::cmp::min(decrypted.len(), buf.remaining());
                buf.put_slice(&decrypted[..n]);
                if n < decrypted.len() {
                    let me = self.as_mut().project();
                    me.overflow.extend_from_slice(&decrypted[n..]);
                }
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
    A: AeadInOut,
    A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
    NonceSize<A, S>: ArraySize,
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

    use aead_stream::{DecryptorLE31, EncryptorLE31};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
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
                    EncryptorLE31::from_aead(
                        XChaCha20Poly1305::new((&key).into()),
                        (&start_nonce).into(),
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

        let decryptor = DecryptorLE31::from_aead(
            XChaCha20Poly1305::new((&key).into()),
            (&start_nonce).into(),
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

        let decryptor = DecryptorLE31::from_aead(
            XChaCha20Poly1305::new((&key).into()),
            (&start_nonce).into(),
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

    #[tokio::test]
    pub async fn test_read_with_header_split_near_buffer_end() {
        let key: [u8; 32] = get_key("key", "group");
        let start_nonce = [0u8; 20];

        let mut encryptor: EncryptorLE31<XChaCha20Poly1305> =
            EncryptorLE31::from_aead(
                XChaCha20Poly1305::new((&key).into()),
                (&start_nonce).into(),
            );

        let mut record1 = {
            let mut encrypted = encryptor.encrypt_next("hi".as_bytes()).unwrap();
            let mut record = Vec::new();
            record.extend((encrypted.len() as u32).to_le_bytes());
            record.append(&mut encrypted);
            record
        };

        let record2 = {
            let mut encrypted = encryptor.encrypt_next("there".as_bytes()).unwrap();
            let mut record = Vec::new();
            record.extend((encrypted.len() as u32).to_le_bytes());
            record.append(&mut encrypted);
            record
        };

        // Only the first 2 bytes of message 2's 4-byte length header will already be
        // sitting in the internal buffer; the rest arrives later through the reader.
        let (record2_head, record2_tail) = record2.split_at(2);

        let (rx, mut tx) = tokio::io::duplex(4096);
        tx.write_all(record2_tail).await.unwrap();

        let decryptor = DecryptorLE31::from_aead(
            XChaCha20Poly1305::new((&key).into()),
            (&start_nonce).into(),
        );
        let mut reader = ReadHalf::with_capacity(rx, decryptor, record1.len() + record2_head.len());

        // Pre-load message 1 in full, plus the first 2 bytes of message 2's header,
        // filling the internal buffer to exactly its capacity. Once message 1 is
        // consumed, `pos` sits only 2 bytes away from the end of the buffer, with
        // less than 4 bytes available for message 2's header.
        record1.extend_from_slice(record2_head);
        reader.buffer = record1.clone();
        reader.cap = record1.len();
        reader.pos = 0;

        let mut buf = [0u8; 1024];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hi");

        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"there");
    }

    #[tokio::test]
    pub async fn test_read_buffer_smaller_than_message() {
        let key: [u8; 32] = get_key("key", "group");
        let start_nonce = [0u8; 20];

        let (rx, mut tx) = tokio::io::duplex(4096);

        tokio::spawn(async move {
            let mut encryptor: EncryptorLE31<XChaCha20Poly1305> =
                EncryptorLE31::from_aead(
                    XChaCha20Poly1305::new((&key).into()),
                    (&start_nonce).into(),
                );

            let content = "a".repeat(500);
            let mut encrypted = encryptor.encrypt_next(content.as_bytes()).unwrap();
            let mut encrypted_content = Vec::new();
            encrypted_content.extend((encrypted.len() as u32).to_le_bytes());
            encrypted_content.append(&mut encrypted);

            let _ = tx.write_all(&encrypted_content).await;
        });

        let decryptor = DecryptorLE31::from_aead(
            XChaCha20Poly1305::new((&key).into()),
            (&start_nonce).into(),
        );
        let mut reader = ReadHalf::new(rx, decryptor);

        // The caller's buffer is far smaller than the 500-byte decrypted message, so
        // delivering it must span several `read` calls instead of erroring/dropping data.
        let mut plain_content = String::new();
        let mut small_buf = [0u8; 64];
        loop {
            let n = reader.read(&mut small_buf).await.unwrap();
            if n == 0 {
                break;
            }
            plain_content.push_str(std::str::from_utf8(&small_buf[..n]).unwrap());
        }

        assert_eq!(plain_content, "a".repeat(500));
    }
}
