package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// References https://stackoverflow.com/questions/5889238/why-is-xor-the-default-way-to-combine-hashes

// Constants for 32-bit and 64-bit hashing
const (
	prime32 = 0x9e3779b9         // Golden ratio constant (32-bit)
	prime64 = 0x517cc1b727220a95 // Golden ratio constant (64-bit)
)

// SphinxHash is a structure that encapsulates the combination and hashing logic
type SphinxHash struct {
	bitSize int
}

// NewSphinxHash creates a new SphinxHash with a specific bit size for the hash
func NewSphinxHash(bitSize int) *SphinxHash {
	return &SphinxHash{
		bitSize: bitSize,
	}
}

// secureRandomUint64 generates a cryptographically secure random uint64
func secureRandomUint64() (uint64, error) {
	var buf [8]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

// hashData calculates the combined hash of data using SHA-2 and SHAKE based on the bit size
func (s *SphinxHash) hashData(data []byte) []byte {
	var sha2Hash []byte
	var shakeHash []byte

	// Generate SHA2 and SHAKE hashes based on the bit size
	switch s.bitSize {
	case 128:
		// Use SHAKE128 to generate a 128-bit hash
		shake := sha3.NewShake128()
		shake.Write(data)
		shakeHash = make([]byte, 16) // 128 bits = 16 bytes
		shake.Read(shakeHash)
		return shakeHash
	case 256:
		// Use SHA-256 to generate a 256-bit hash
		hash := sha256.Sum256(data) // Returns [32]byte
		sha2Hash = hash[:]
		// Use SHAKE128 to generate a 256-bit hash
		shake := sha3.NewShake128()
		shake.Write(data)
		shakeHash = make([]byte, 32) // 256 bits = 32 bytes
		shake.Read(shakeHash)
		// Combine SHA-2 and SHAKE hashes
		return s.sphinxHash(sha2Hash, shakeHash, prime32)
	case 384:
		// Use SHA-384 to generate a 384-bit hash
		hash := sha512.Sum384(data) // Returns [48]byte
		sha2Hash = hash[:]
		// Use SHAKE128 to generate a 384-bit hash
		shake := sha3.NewShake128()
		shake.Write(data)
		shakeHash = make([]byte, 48) // 384 bits = 48 bytes
		shake.Read(shakeHash)
		// Combine SHA-2 and SHAKE hashes
		return s.sphinxHash(sha2Hash, shakeHash, prime64)
	case 512:
		// Use SHA-512 to generate a 512-bit hash
		hash := sha512.Sum512(data) // Returns [64]byte
		sha2Hash = hash[:]
		// Use SHAKE128 to generate a 512-bit hash
		shake := sha3.NewShake128()
		shake.Write(data)
		shakeHash = make([]byte, 64) // 512 bits = 64 bytes
		shake.Read(shakeHash)
		// Combine SHA-2 and SHAKE hashes
		return s.sphinxHash(sha2Hash, shakeHash, prime64)
	default:
		// Default to 256-bit SHAKE256 if no bit size matches
		shake := sha3.NewShake256()
		shake.Write(data)
		shakeHash = make([]byte, 32) // 256 bits = 32 bytes
		shake.Read(shakeHash)
		return shakeHash
	}
}

// sphinxHash combines two byte slices by applying a combination logic using a prime constant.
func (s *SphinxHash) sphinxHash(hash1, hash2 []byte, primeConstant uint64) []byte {
	if len(hash1) != len(hash2) {
		panic("hash1 and hash2 must have the same length")
	}

	// Optionally introduce a random factor for added variability
	randomFactor, err := secureRandomUint64()
	if err != nil {
		panic("failed to generate random factor")
	}

	// Resulting hash combination
	sphinxHash := make([]byte, len(hash1))
	for i := 0; i < len(hash1); i++ {
		// Convert bytes to uint64 for combination
		h1 := uint64(hash1[i])
		h2 := uint64(hash2[i])
		// Combine hash values using addition, bit shifting, and multiplication
		sphinxHash[i] = byte((h1*3 + h2 + randomFactor) ^ primeConstant)
		// h1*3: Multiply the first hash value by 3
		// h2: Add the second hash value
		// randomFactor: Added to increase variability
		// ^ primeConstant: XOR with a constant for final mixing
	}
	return sphinxHash
}

func main() {
	// Example data to hash
	data := []byte("Hello world!")

	// Print the original data
	fmt.Printf("Original Data: %s\n", data)

	// Create a new SphinxHash object with the chosen bit size
	sphinx := NewSphinxHash(256) // Change this to 128, 256, 384, or 512

	// Hash the data using the SphinxHash object
	sphinxHash := sphinx.hashData(data)

	// Print the combined hash
	fmt.Printf("Sphinx Hash (%d-bit) %d bytes: %x\n", sphinx.bitSize, len(sphinxHash), sphinxHash)
}
