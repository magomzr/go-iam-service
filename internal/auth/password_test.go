package auth

import (
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	password := "secreto123"

	hash, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}

	if hash == password {
		t.Error("hash should not equal plaintext password")
	}

	if !verifyPassword(password, hash) {
		t.Error("verifyPassword should return true for correct password")
	}
}

func TestVerifyWrongPassword(t *testing.T) {
	hash, _ := hashPassword("correcta")

	if verifyPassword("incorrecta", hash) {
		t.Error("verifyPassword should return false for wrong password")
	}
}

func TestHashesAreDifferentForSamePassword(t *testing.T) {
	// Argon2id usa salt aleatorio — dos hashes del mismo password deben ser distintos
	hash1, _ := hashPassword("misma-password")
	hash2, _ := hashPassword("misma-password")

	if hash1 == hash2 {
		t.Error("two hashes of the same password should differ due to random salt")
	}
}

func TestVerifyInvalidHash(t *testing.T) {
	if verifyPassword("cualquier-cosa", "hash-malformado") {
		t.Error("verifyPassword should return false for malformed hash")
	}
}

func TestVerifyEmptyHash(t *testing.T) {
	if verifyPassword("password", "") {
		t.Error("verifyPassword should return false for empty hash")
	}
}

func BenchmarkHashPassword(b *testing.B) {
	for b.Loop() {
		_, err := hashPassword("mi-password-de-prueba")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	hash, err := hashPassword("mi-password-de-prueba")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for b.Loop() {
		verifyPassword("mi-password-de-prueba", hash)
	}
}

func BenchmarkVerifyPasswordWrong(b *testing.B) {
	hash, err := hashPassword("mi-password-de-prueba")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for b.Loop() {
		verifyPassword("password-incorrecta", hash)
	}
}
