package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const MaxLength = 128

const (
	argon2Version    = argon2.Version
	argon2MemoryKiB  = 19 * 1024
	argon2Iterations = 2
	argon2Parallelism = 1
	argon2KeyLength  = 32
	argon2SaltLength = 16
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}

	salt := make([]byte, argon2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}

	derivedKey := argon2.IDKey(
		[]byte(password),
		salt,
		argon2Iterations,
		argon2MemoryKiB,
		argon2Parallelism,
		argon2KeyLength,
	)

	return encodeArgon2idHash(argon2idHash{
		version:     argon2Version,
		memoryKiB:   argon2MemoryKiB,
		iterations:  argon2Iterations,
		parallelism: argon2Parallelism,
		salt:        salt,
		derivedKey:  derivedKey,
	}), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}

	// Legacy SHA-256 hash.
	expectedHash, ok := decodeLegacyHash(encodedHash)
	if ok {
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
	}

	// Argon2id hash.
	passwordHash, ok := parseArgon2idHash(encodedHash)
	if !ok || passwordHash.version != argon2Version {
		return false
	}

	candidateHash := argon2.IDKey(
		[]byte(password),
		passwordHash.salt,
		passwordHash.iterations,
		passwordHash.memoryKiB,
		passwordHash.parallelism,
		uint32(len(passwordHash.derivedKey)),
	)

	return subtle.ConstantTimeCompare(candidateHash, passwordHash.derivedKey) == 1
}

func NeedsRehash(encodedHash string) bool {
	if _, ok := decodeLegacyHash(encodedHash); ok {
		return true
	}
	passwordHash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}
	if passwordHash.version != argon2Version {
		return true
	}
	if passwordHash.memoryKiB != argon2MemoryKiB {
		return true
	}
	if passwordHash.iterations != argon2Iterations {
		return true
	}
	if passwordHash.parallelism != argon2Parallelism {
		return true
	}
	if len(passwordHash.derivedKey) != argon2KeyLength {
		return true
	}
	return false
}
