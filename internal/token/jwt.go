package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type Manager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

type Claims struct {
	jwt.RegisteredClaims
	Email       string   `json:"email"`
	Permissions []string `json:"permissions"`
}

func NewManager(privateKeyPath, publicKeyPath, keyID string, accessTTL, refreshTTL time.Duration) (*Manager, error) {
	privBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, errors.New("reading private key failed")
	}

	pubBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, errors.New("reading public key failed")
	}

	privBlock, _ := pem.Decode(privBytes)
	if privBlock == nil {
		return nil, errors.New("decoding private key PEM failed")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		privateKey, err = x509.ParsePKCS1PrivateKey(privBlock.Bytes)
		if err != nil {
			return nil, errors.New("parsing private key failed")
		}
	}

	rsaPriv, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}

	pubBlock, _ := pem.Decode(pubBytes)
	if pubBlock == nil {
		return nil, errors.New("decoding public key PEM failed")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, errors.New("parsing public key failed")
	}

	rsaPub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}

	return &Manager{
		privateKey: rsaPriv,
		publicKey:  rsaPub,
		keyID:      keyID,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}, nil
}

func (m *Manager) SignAccessToken(userID, email string, permissions []string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.accessTTL)),
			ID:        uuid.NewString(),
		},
		Email:       email,
		Permissions: permissions,
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = m.keyID

	return t.SignedString(m.privateKey)
}

func (m *Manager) VerifyAccessToken(tokenStr string) (*Claims, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("invalid signing method")
		}
		return m.publicKey, nil
	})
	if err != nil {
		log.Debug().Bool("expired", errors.Is(err, jwt.ErrTokenExpired)).Msg("token verification failed")
		return nil, errors.New("invalid or expired token")
	}

	claims, ok := t.Claims.(*Claims)
	if !ok || !t.Valid {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

func (m *Manager) JWKS() map[string]any {
	pub := m.publicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

	return map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": m.keyID,
				"n":   n,
				"e":   e,
			},
		},
	}
}

func HashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func GenerateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func NewManagerFromKeys(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, keyID string, accessTTL, refreshTTL time.Duration) *Manager {
	return &Manager{
		privateKey: privateKey,
		publicKey:  publicKey,
		keyID:      keyID,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}
