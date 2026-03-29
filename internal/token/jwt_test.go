package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/magomzr/go-iam-service/internal/token"
)

// generateTestManager crea un Manager con claves RSA generadas en memoria
// para tests — sin necesidad de archivos PEM en disco.
func generateTestManager(t *testing.T) *token.Manager {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	return token.NewManagerFromKeys(privateKey, &privateKey.PublicKey, "test-kid", 15*time.Minute, 7*24*time.Hour)
}

func TestSignAndVerifyAccessToken(t *testing.T) {
	tm := generateTestManager(t)

	userID := "4bb2f8b5-86a6-45c2-84f4-2a10cae1fd86"
	email := "mario@test.com"
	permissions := []string{"read:users", "manage:roles"}

	tokenStr, err := tm.SignAccessToken(userID, email, permissions)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}

	claims, err := tm.VerifyAccessToken(tokenStr)
	if err != nil {
		t.Fatalf("verifying token: %v", err)
	}

	if claims.Subject != userID {
		t.Errorf("expected sub %q, got %q", userID, claims.Subject)
	}
	if claims.Email != email {
		t.Errorf("expected email %q, got %q", email, claims.Email)
	}
	if len(claims.Permissions) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(claims.Permissions))
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	// TTL de -1 minuto — el token nace ya expirado
	tm := token.NewManagerFromKeys(privateKey, &privateKey.PublicKey, "test-kid", -1*time.Minute, 0)

	tokenStr, err := tm.SignAccessToken("some-id", "test@test.com", nil)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}

	_, err = tm.VerifyAccessToken(tokenStr)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestVerifyTamperedToken(t *testing.T) {
	tm := generateTestManager(t)

	tokenStr, _ := tm.SignAccessToken("some-id", "test@test.com", nil)

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatal("expected 3 parts in JWT")
	}

	parts[1] = parts[1] + "tampered"
	tampered := strings.Join(parts, ".")

	_, err := tm.VerifyAccessToken(tampered)
	if err == nil {
		t.Error("expected error for tampered token, got nil")
	}
}

func TestHashTokenDeterministic(t *testing.T) {
	raw := "mi-refresh-token-secreto"

	hash1 := token.HashToken(raw)
	hash2 := token.HashToken(raw)

	if hash1 != hash2 {
		t.Error("HashToken should be deterministic for the same input")
	}
}

func TestHashTokenDifferentInputs(t *testing.T) {
	hash1 := token.HashToken("token-a")
	hash2 := token.HashToken("token-b")

	if hash1 == hash2 {
		t.Error("different inputs should produce different hashes")
	}
}

func generateTestManager2(b *testing.B) *token.Manager {
	b.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("generating RSA key: %v", err)
	}
	return token.NewManagerFromKeys(privateKey, &privateKey.PublicKey, "test-kid", 15*time.Minute, 7*24*time.Hour)
}

func BenchmarkSignAccessToken(b *testing.B) {
	tm := generateTestManager2(b)
	permissions := []string{"read:users", "manage:roles", "create:posts", "delete:reports"}

	for b.Loop() {
		_, err := tm.SignAccessToken("4bb2f8b5-86a6-45c2-84f4-2a10cae1fd86", "mario@test.com", permissions)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAccessToken(b *testing.B) {
	tm := generateTestManager2(b)

	tokenStr, err := tm.SignAccessToken("4bb2f8b5-86a6-45c2-84f4-2a10cae1fd86", "mario@test.com", []string{"read:users"})
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for b.Loop() {
		_, err := tm.VerifyAccessToken(tokenStr)
		if err != nil {
			b.Fatal(err)
		}
	}
}
