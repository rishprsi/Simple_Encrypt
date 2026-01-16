package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// pbkdf2Key derives a key using PBKDF2 with SHA-256
func pbkdf2Key(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var key []byte
	for i := 1; i <= numBlocks; i++ {
		prf.Reset()
		prf.Write(salt)
		blockNum := make([]byte, 4)
		binary.BigEndian.PutUint32(blockNum, uint32(i))
		prf.Write(blockNum)
		u := prf.Sum(nil)
		block := make([]byte, hashLen)
		copy(block, u)
		for j := 1; j < iterations; j++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for k := 0; k < hashLen; k++ {
				block[k] ^= u[k]
			}
		}
		key = append(key, block...)
	}
	return key[:keyLen]
}

// encode encrypts the input with AES-256-GCM using PBKDF2 key derivation
func encode(inputPath, secret string, expirySeconds int64, filename string, text bool) (string, error) {
	var plaintext []byte
	var err error
	if text {
		plaintext, err = io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("read stdin: %w", err)
		}
	} else {
		plaintext, err = os.ReadFile(inputPath)
		if err != nil {
			return "", fmt.Errorf("read input: %w", err)
		}
		if filename == "" {
			filename = filepath.Base(inputPath)
		}
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt: %w", err)
	}
	iterations := 200000
	key := pbkdf2Key([]byte(secret), salt, iterations, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm init: %w", err)
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("iv: %w", err)
	}
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	expiry := uint64(0)
	if expirySeconds > 0 {
		expiry = uint64(time.Now().Unix() + expirySeconds)
	}
	header := make([]byte, 8)
	binary.BigEndian.PutUint64(header, expiry)
	iterationsBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(iterationsBytes, uint32(iterations))
	nameBytes := []byte(filename)
	nameLen := byte(len(nameBytes))
	payloadLen := 8 + 16 + 4 + 1 + len(nameBytes) + 12 + len(ciphertext)
	payload := make([]byte, payloadLen)
	off := 0
	copy(payload[off:], header)
	off += 8
	copy(payload[off:], salt)
	off += 16
	copy(payload[off:], iterationsBytes)
	off += 4
	payload[off] = nameLen
	off += 1
	copy(payload[off:], nameBytes)
	off += len(nameBytes)
	copy(payload[off:], iv)
	off += 12
	copy(payload[off:], ciphertext)
	encoded := base64.StdEncoding.EncodeToString(payload)
	return encoded, nil
}

// decode decrypts a base64 payload and writes the plaintext to a file in the output directory
func decode(inputPath, secret, outputDir string) error {
	var payload []byte
	var err error
	if inputPath == "-" {
		payload, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
		// Assume it's base64 string
		payload, err = base64.StdEncoding.DecodeString(string(payload))
		if err != nil {
			return fmt.Errorf("base64 decode: %w", err)
		}
	} else {
		encodedBytes, err := os.ReadFile(inputPath)
		if err != nil {
			return fmt.Errorf("read input: %w", err)
		}
		payload, err = base64.StdEncoding.DecodeString(string(encodedBytes))
		if err != nil {
			return fmt.Errorf("base64 decode: %w", err)
		}
	}
	if len(payload) < 8+16+4+1+12 {
		return fmt.Errorf("payload too short")
	}
	off := 0
	expiry := binary.BigEndian.Uint64(payload[off : off+8])
	off += 8
	salt := payload[off : off+16]
	off += 16
	iterations := binary.BigEndian.Uint32(payload[off : off+4])
	off += 4
	nameLen := payload[off]
	off += 1
	nameBytes := payload[off : off+int(nameLen)]
	filename := string(nameBytes)
	off += int(nameLen)
	iv := payload[off : off+12]
	off += 12
	ciphertext := payload[off:]
	key := pbkdf2Key([]byte(secret), salt, int(iterations), 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("aes init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm init: %w", err)
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if expiry > 0 && int64(expiry) < time.Now().Unix() {
		return fmt.Errorf("payload expired")
	}
	outputPath := filepath.Join(outputDir, filename)
	return os.WriteFile(outputPath, plaintext, 0644)
}

func main() {
	cmd := flag.String("cmd", "", "encode or decode")
	input := flag.String("input", "", "input file path or - for stdin")
	output := flag.String("output", "", "output file path or directory, or - for stdout")
	secret := flag.String("secret", "", "secret key")
	expiry := flag.Int64("expiry", 0, "expiry seconds")
	filename := flag.String("filename", "", "filename for text input")
	text := flag.Bool("text", false, "input is text from stdin")
	flag.Parse()
	if *cmd == "" || *secret == "" {
		fmt.Println("Usage: go run . -cmd encode|decode [flags]")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if *cmd == "encode" {
		if *text && *filename == "" {
			fmt.Fprintln(os.Stderr, "filename required for text input")
			os.Exit(1)
		}
		encoded, err := encode(*input, *secret, *expiry, *filename, *text)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(2)
		}
		if *output == "-" {
			fmt.Print(encoded)
		} else if *output != "" {
			os.WriteFile(*output, []byte(encoded), 0644)
		} else {
			fmt.Print(encoded)
		}
	} else if *cmd == "decode" {
		outputDir := *output
		if outputDir == "" {
			outputDir = "."
		}
		err := decode(*input, *secret, outputDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(2)
		}
		fmt.Println("Decrypted file written.")
	} else {
		fmt.Println("Unknown command:", *cmd)
		os.Exit(1)
	}
}
