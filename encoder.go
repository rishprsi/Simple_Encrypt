package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"time"
)

// encodeFile encrypts the input file with AES-256-GCM using a key derived from secret
// and writes a base64 payload to output. If timeoutSeconds > 0, an expiry header is
// prepended to enforce a time-based decryption expiry.
func encodeFile(inputPath, outputPath, secret string, timeoutSeconds int64) error {
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return fmt.Errorf("aes init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm init: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	var payload []byte
	if timeoutSeconds > 0 {
		expiry := uint64(time.Now().Unix() + timeoutSeconds)
		header := make([]byte, 8)
		binary.BigEndian.PutUint64(header, expiry)
		body := append(nonce, ciphertext...)
		payload = append(header, body...)
	} else {
		payload = append(nonce, ciphertext...)
	}
	encoded := base64.StdEncoding.EncodeToString(payload)
	if err := os.WriteFile(outputPath, []byte(encoded), 0644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// decodeFile decrypts a base64-encoded payload produced by encodeFile using the same secret.
// If useHeader is true, it validates the expiry timestamp before decrypting.
func decodeFile(encodedPath, decodedPath, secret string, useHeader bool) error {
	encodedBytes, err := os.ReadFile(encodedPath)
	if err != nil {
		return fmt.Errorf("open encoded: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(string(encodedBytes))
	if err != nil {
		return fmt.Errorf("base64 decode: %w", err)
	}
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return fmt.Errorf("aes init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm init: %w", err)
	}
	nonceSize := gcm.NonceSize()
	offset := 0
	if useHeader {
		if len(payload) < 8+nonceSize {
			return fmt.Errorf("payload too small for header")
		}
		expiry := binary.BigEndian.Uint64(payload[:8])
		if int64(expiry) < time.Now().Unix() {
			return fmt.Errorf("payload expired")
		}
		offset = 8
	}
	payload = payload[offset:]
	if len(payload) < nonceSize {
		return fmt.Errorf("payload too small for nonce")
	}
	nonce := payload[:nonceSize]
	ciphertext := payload[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if err := os.WriteFile(decodedPath, plaintext, 0644); err != nil {
		return fmt.Errorf("write decoded: %w", err)
	}
	return nil
}

func main() {
	// Usage: go run . <encode|decode> <input> <output> <secret> [timeout_seconds]
	if len(os.Args) < 5 {
		fmt.Println("Usage: go run . <encode|decode> <input> <output> <secret> [timeout_seconds]")
		fmt.Println("  encode: encrypt input file with secret; optional timeout_seconds to expire")
		fmt.Println("  decode: decrypt base64 payload; will fail if expired when timeout was set")
		os.Exit(1)
	}
	cmd, in, out := os.Args[1], os.Args[2], os.Args[3]
	secret := os.Args[4]
	var timeout int64 = 0
	useHeader := false
	if len(os.Args) >= 6 {
		val, err := strconv.ParseInt(os.Args[5], 10, 64)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid timeout_seconds; must be integer")
			os.Exit(2)
		}
		timeout = val
		if timeout > 0 {
			useHeader = true
		}
	}
	var err error
	switch cmd {
	case "encode":
		err = encodeFile(in, out, secret, timeout)
	case "decode":
		err = decodeFile(in, out, secret, useHeader)
	default:
		fmt.Println("Unknown command:", cmd)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(2)
	}
	fmt.Println("Done.")
}
