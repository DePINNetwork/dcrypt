# Streaming Symmetric Encryption (`symmetric/streaming`)

This module provides APIs for streaming symmetric encryption and decryption. Streaming is essential for handling large files or data streams that cannot fit entirely into memory. The implementations here manage chunking of data, per-chunk nonce derivation (where applicable), and interaction with `std::io::Read` and `std::io::Write` traits.

## Core Traits

1.  **`StreamingEncrypt<W: Write>`**:
    *   **Purpose**: Defines the interface for a streaming encryption context.
    *   **Methods**:
        *   `write(&mut self, data: &[u8]) -> Result<()>`: Encrypts a chunk of plaintext `data` and writes the resulting ciphertext to the underlying writer `W`. This can be called multiple times.
        *   `finalize(self) -> Result<W>`: Finalizes the encryption stream. This encrypts any remaining buffered plaintext, writes out any finalization data (like an end-of-stream marker or final authentication tag if the scheme requires it at the end), and returns the underlying writer. This method consumes the encryptor.

2.  **`StreamingDecrypt<R: Read>`**:
    *   **Purpose**: Defines the interface for a streaming decryption context.
    *   **Methods**:
        *   `read(&mut self, buf: &mut [u8]) -> Result<usize>`: Reads encrypted data from the underlying reader `R`, decrypts it, and fills `buf` with the resulting plaintext. Returns the number of plaintext bytes written to `buf`. Returns `Ok(0)` if the end of the stream is reached and successfully authenticated.

## Implemented Streaming Schemes

The module provides streaming implementations for the AEAD ciphers available in `dcrypt-symmetric`:

1.  **ChaCha20Poly1305 Streaming (`chacha20poly1305.rs`)**:
    *   **`ChaCha20Poly1305EncryptStream<W: Write>`**:
        *   Manages encryption of data in chunks (e.g., 16KB).
        *   **Nonce Management**: Writes an initial "base nonce" to the stream. For each subsequent chunk of data, it derives a unique chunk nonce by XORing the base nonce with an incrementing counter. This counter is also written to the stream alongside the ciphertext chunk.
        *   **Format**: The output stream consists of:
            1.  Base Nonce (12 bytes).
            2.  For each chunk:
                *   Chunk marker (1 byte, `0x01` for data chunk).
                *   Chunk counter (4 bytes, big-endian).
                *   Ciphertext length (4 bytes, big-endian).
                *   Ciphertext (including AEAD tag for that chunk).
            3.  End-of-stream marker (1 byte, `0x00`).
    *   **`ChaCha20Poly1305DecryptStream<R: Read>`**:
        *   Reads the base nonce from the stream.
        *   For each chunk, reads the marker, counter, and ciphertext.
        *   Derives the chunk nonce using the base nonce and the read counter.
        *   Decrypts and verifies the chunk.
        *   Stops when the end-of-stream marker is encountered.

2.  **AES-GCM Streaming (`gcm.rs`)**:
    *   **`Aes128GcmEncryptStream<W: Write>`** and **`Aes256GcmEncryptStream<W: Write>`**.
    *   **`Aes128GcmDecryptStream<R: Read>`** and **`Aes256GcmDecryptStream<R: Read>`**.
    *   **Nonce Management and Format**: Follows the exact same chunking, per-chunk nonce derivation, and stream format strategy as `ChaCha20Poly1305EncryptStream` and `ChaCha20Poly1305DecryptStream`. The only difference is the underlying AEAD cipher used (AES-128-GCM or AES-256-GCM).

## Utility Functions

The modules also provide convenient file encryption/decryption functions that wrap the streaming APIs:
- In `chacha20poly1305.rs`:
    * `encrypt_file<R: Read, W: Write>(...) -> Result<()>`
    * `decrypt_file<R: Read, W: Write>(...) -> Result<()>`
- In `gcm.rs`:
    * `encrypt_file_aes128<R: Read, W: Write>(...) -> Result<()>`
    * `decrypt_file_aes128<R: Read, W: Write>(...) -> Result<()>`
    * `encrypt_file_aes256<R: Read, W: Write>(...) -> Result<()>`
    * `decrypt_file_aes256<R: Read, W: Write>(...) -> Result<()>`

## Usage Example (AES-128-GCM Streaming)

```rust
use dcrypt_symmetric::aes::Aes128Key;
use dcrypt_symmetric::streaming::gcm::{Aes128GcmEncryptStream, Aes128GcmDecryptStream};
use dcrypt_symmetric::streaming::{StreamingEncrypt, StreamingDecrypt};
use dcrypt_symmetric::error::Result;
use std::io::{Cursor, Read, Write}; // For in-memory Read/Write

fn streaming_aes128_gcm_example() -> Result<()> {
    let key = Aes128Key::generate();
    let aad = Some(b"Authenticated context for streaming");

    // --- Encryption ---
    let mut ciphertext_buffer = Vec::new(); // In-memory buffer for encrypted data
    // Scope for the encrypt_stream to ensure finalize is called via drop or explicitly
    {
        let mut writer_cursor = Cursor::new(&mut ciphertext_buffer);
        let mut encrypt_stream = Aes128GcmEncryptStream::new(writer_cursor, &key, aad)?;

        encrypt_stream.write(b"This is the first segment of a long message.")?;
        encrypt_stream.write(b"Followed by a second segment.")?;
        encrypt_stream.write(b"And finally, the last segment.")?;

        // Finalize the stream (consumes the encrypt_stream)
        let _ = encrypt_stream.finalize()?;
    } // encrypt_stream is dropped here, finalize would be called if not done explicitly.

    println!("Total encrypted data size (incl. header & metadata): {} bytes", ciphertext_buffer.len());

    // --- Decryption ---
    let mut reader_cursor = Cursor::new(ciphertext_buffer);
    let mut decrypt_stream = Aes128GcmDecryptStream::new(reader_cursor, &key, aad)?;

    let mut decrypted_data = Vec::new();
    let mut read_buf = [0u8; 1024]; // Buffer to read decrypted chunks into

    loop {
        let bytes_read = decrypt_stream.read(&mut read_buf)?;
        if bytes_read == 0 { // End of stream
            break;
        }
        decrypted_data.extend_from_slice(&read_buf[..bytes_read]);
    }

    let original_message = b"This is the first segment of a long message.Followed by a second segment.And finally, the last segment.";
    assert_eq!(original_message, decrypted_data.as_slice());
    println!("Streaming decryption successful: {}", String::from_utf8_lossy(&decrypted_data));

    Ok(())
}

// fn main() {
//     streaming_aes128_gcm_example().expect("Streaming AES-128-GCM example failed.");
// }
```

## Security Considerations

-   **Nonce Derivation**: The streaming protocols implemented here derive per-chunk nonces from a single base nonce and an incrementing counter. This ensures that the underlying AEAD primitive (which requires unique nonces per key) is used correctly for each chunk. The base nonce itself must be unique for each overall stream encrypted with the same key.
-   **AAD**: If Associated Data is used, it's applied to each chunk's AEAD operation. This means the same AAD protects all chunks.
-   **Error Handling**: `std::io::Error`s from read/write operations are converted to `symmetric::error::Error::Io`. AEAD decryption errors (tag mismatch) will result in `Error::Primitive(PrimitiveError::Authentication { .. })`.
-   **Stream Integrity**: Each chunk is authenticated individually. The end-of-stream marker helps detect premature truncation, but a sophisticated attacker could potentially reorder or remove authenticated chunks if the higher-level application doesn't also protect against this (e.g., by sequencing data or using a manifest).