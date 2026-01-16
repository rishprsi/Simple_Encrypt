# Encryption Tool Reference

## Overview
This is a command-line encryption/decryption tool implemented in Go, designed to provide secure file and text encryption using AES-256-GCM with PBKDF2 key derivation. It mirrors the functionality of a web-based JavaScript version, allowing interoperability between the two.

## Technologies Used

### Core Technologies
- **Go**: The programming language used for the CLI implementation.
- **AES-256-GCM**: Symmetric encryption algorithm with authenticated encryption.
- **PBKDF2**: Password-Based Key Derivation Function 2, used to derive encryption keys from a secret passphrase.
- **Base64**: Encoding scheme for transmitting binary data as text.

### Libraries and Standards
- **crypto/aes**: Go standard library for AES encryption.
- **crypto/cipher**: For GCM mode.
- **crypto/hmac**: For HMAC in PBKDF2 implementation.
- **crypto/sha256**: Hash function used in key derivation.
- **encoding/base64**: For base64 encoding/decoding.
- **flag**: For command-line argument parsing.

### Payload Structure
The encrypted payload format is:
- Expiry timestamp (8 bytes, big-endian uint64)
- Salt (16 bytes)
- Iterations (4 bytes, big-endian uint32)
- Filename length (1 byte)
- Filename bytes (variable)
- IV (12 bytes)
- Ciphertext (variable)

## How the App Works

### Key Derivation
1. User provides a secret passphrase.
2. PBKDF2 is applied with:
   - Salt: 16 random bytes
   - Iterations: 200,000
   - Hash: SHA-256
   - Output: 32-byte key for AES-256

### Encryption Process
1. Input: File or text from stdin.
2. Generate random IV (12 bytes).
3. Encrypt plaintext with AES-256-GCM using derived key and IV.
4. Construct payload with expiry, salt, iterations, filename, IV, and ciphertext.
5. Base64-encode the payload.
6. Output base64 string to file or stdout.

### Decryption Process
1. Input: Base64-encoded payload from file or stdin.
2. Base64-decode to binary payload.
3. Parse payload: extract expiry, salt, iterations, filename, IV, ciphertext.
4. Check expiry if set.
5. Derive key using same PBKDF2 parameters.
6. Decrypt ciphertext with AES-256-GCM.
7. Write plaintext to file using embedded filename.

### Command-Line Usage
- **Encode**: `go run encoder.go -cmd encode -input <file> -secret <key> -expiry <seconds> -filename <name> -output <file>`
- **Decode**: `go run encoder.go -cmd decode -input <file> -secret <key> -output <dir>`

### Security Notes
- Uses strong key derivation (PBKDF2 with high iteration count).
- Authenticated encryption prevents tampering.
- Optional expiry prevents indefinite access.
- Secrets should be managed securely (not hardcoded).

## Interoperability
The Go CLI produces payloads compatible with the JavaScript web app, allowing encryption in one and decryption in the other.

## Tags
#encryption #go #aes #pbkdf2 #cli #security