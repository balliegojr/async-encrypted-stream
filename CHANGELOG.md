# 0.2.0


### Fixes
- Fix a panic in the read half when a message's length header arrives split across reads and lands near the end of the internal buffer
- Fix data loss and a spurious error when a decrypted message is larger than the caller's read buffer; the remainder is now buffered internally and delivered on subsequent reads

### Breaking
- Update dependencies

# 0.1.2 

### Fixes
- Prevent panicking behavior if read buffer is smaller than decrypted message

# 0.1.1 (03-08-2023)

### Fixes
- Fix internal error logic to return an error when fail to decrypt message

### Breaking
- Add "std" chacha20poly1305 feature in the dependencies

# 0.1.0 (04-07-2023)

Initial Release
