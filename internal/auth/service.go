package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"

	"github.com/magomzr/go-iam-service/internal/db/sqlcgen"
	"github.com/magomzr/go-iam-service/internal/pghelper"
	"github.com/magomzr/go-iam-service/internal/token"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrTokenInvalid       = errors.New("refresh token invalid or expired")
	ErrTokenReused        = errors.New("refresh token reuse detected — session revoked")
)

const (
	argonMemory      uint32 = 64 * 1024
	argonIterations  uint32 = 3
	argonParallelism uint8  = 2
	argonSaltLen            = 16
	argonKeyLen      uint32 = 32
)

type Service struct {
	pool         *pgxpool.Pool
	queries      *sqlcgen.Queries
	tokenManager *token.Manager
	refreshTTL   time.Duration
}

func NewService(pool *pgxpool.Pool, tm *token.Manager, refreshTTL time.Duration) *Service {
	return &Service{
		pool:         pool,
		queries:      sqlcgen.New(pool),
		tokenManager: tm,
		refreshTTL:   refreshTTL,
	}
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

func (s *Service) Register(ctx context.Context, email, password string) error {
	hash, err := hashPassword(password)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	_, err = s.queries.CreateUser(ctx, sqlcgen.CreateUserParams{
		Email:    email,
		Password: hash,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return ErrUserAlreadyExists
		}
		return fmt.Errorf("creating user: %w", err)
	}

	return nil
}

func (s *Service) Login(ctx context.Context, email, password string) (*TokenPair, error) {
	user, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("fetching user: %w", err)
	}

	if !verifyPassword(password, user.Password) {
		return nil, ErrInvalidCredentials
	}

	return s.issueTokenPair(ctx, user.ID, user.Email)
}

func (s *Service) Refresh(ctx context.Context, rawRefreshToken string) (*TokenPair, error) {
	hash := token.HashToken(rawRefreshToken)

	rt, err := s.queries.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTokenInvalid
		}
		return nil, fmt.Errorf("fetching refresh token: %w", err)
	}

	if rt.Revoked {
		_ = s.queries.RevokeTokenFamily(ctx, rt.Family)
		return nil, ErrTokenReused
	}

	if time.Now().After(pghelper.ToTime(rt.ExpiresAt)) {
		return nil, ErrTokenInvalid
	}

	if err := s.queries.RevokeRefreshToken(ctx, rt.ID); err != nil {
		return nil, fmt.Errorf("revoking token: %w", err)
	}

	user, err := s.queries.GetUserByID(ctx, rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("fetching user: %w", err)
	}

	return s.issueTokenPairWithFamily(ctx, user.ID, user.Email, rt.Family)
}

func (s *Service) Logout(ctx context.Context, userID uuid.UUID) error {
	return s.queries.RevokeAllUserTokens(ctx, pghelper.UUID(userID))
}

func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	user, err := s.queries.GetUserByID(ctx, pghelper.UUID(userID))
	if err != nil {
		return fmt.Errorf("fetching user: %w", err)
	}

	if !verifyPassword(currentPassword, user.Password) {
		return ErrInvalidCredentials
	}

	hash, err := hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hashing new password: %w", err)
	}

	if _, err := s.queries.UpdateUserPassword(ctx, sqlcgen.UpdateUserPasswordParams{
		ID:       pghelper.UUID(userID),
		Password: hash,
	}); err != nil {
		return fmt.Errorf("updating password: %w", err)
	}

	return s.queries.RevokeAllUserTokens(ctx, pghelper.UUID(userID))
}

func (s *Service) issueTokenPair(ctx context.Context, userID pgtype.UUID, email string) (*TokenPair, error) {
	family := pghelper.UUID(uuid.New())
	return s.issueTokenPairWithFamily(ctx, userID, email, family)
}

func (s *Service) issueTokenPairWithFamily(ctx context.Context, userID pgtype.UUID, email string, family pgtype.UUID) (*TokenPair, error) {
	perms, err := s.queries.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("fetching permissions: %w", err)
	}

	accessToken, err := s.tokenManager.SignAccessToken(pghelper.ToUUID(userID).String(), email, perms)
	if err != nil {
		return nil, fmt.Errorf("signing access token: %w", err)
	}

	rawRefresh, err := token.GenerateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("generating refresh token: %w", err)
	}

	_, err = s.queries.CreateRefreshToken(ctx, sqlcgen.CreateRefreshTokenParams{
		UserID:    userID,
		TokenHash: token.HashToken(rawRefresh),
		Family:    family,
		ExpiresAt: pghelper.Timestamptz(time.Now().Add(s.refreshTTL)),
	})
	if err != nil {
		return nil, fmt.Errorf("storing refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
	}, nil
}

// --- helpers ---
func hashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)

	encoded := fmt.Sprintf("$argon2id$v=19$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
	return encoded, nil
}

func verifyPassword(password, encoded string) bool {
	// formato: $argon2id$v=19$<salt>$<hash>
	parts := strings.Split(encoded, "$")
	// parts[0]="" parts[1]="argon2id" parts[2]="v=19" parts[3]=salt parts[4]=hash
	if len(parts) != 5 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}

	expected, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	actual := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)

	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func isUniqueViolation(err error) bool {
	return err != nil && containsAt(err.Error(), "23505")
}

func containsAt(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
