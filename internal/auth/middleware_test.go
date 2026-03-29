package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/magomzr/go-iam-service/internal/token"
)

func generateTestTokenManager(t *testing.T) *token.Manager {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	return token.NewManagerFromKeys(privateKey, &privateKey.PublicKey, "test-kid", 15*time.Minute, 7*24*time.Hour)
}

func okHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestRequireAuth_MissingHeader(t *testing.T) {
	tm := generateTestTokenManager(t)
	handler := RequireAuth(tm)(http.HandlerFunc(okHandler))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestRequireAuth_InvalidFormat(t *testing.T) {
	tm := generateTestTokenManager(t)
	handler := RequireAuth(tm)(http.HandlerFunc(okHandler))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Token abc123")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestRequireAuth_ValidToken(t *testing.T) {
	tm := generateTestTokenManager(t)
	handler := RequireAuth(tm)(http.HandlerFunc(okHandler))

	tokenStr, err := tm.SignAccessToken(
		"4bb2f8b5-86a6-45c2-84f4-2a10cae1fd86",
		"mario@test.com",
		[]string{"read:users"},
	)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestRequireAuth_InjectsUserID(t *testing.T) {
	tm := generateTestTokenManager(t)

	var capturedID string
	captureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := userIDFromCtx(r)
		capturedID = id.String()
		w.WriteHeader(http.StatusOK)
	})

	handler := RequireAuth(tm)(captureHandler)

	expectedID := "4bb2f8b5-86a6-45c2-84f4-2a10cae1fd86"
	tokenStr, _ := tm.SignAccessToken(expectedID, "mario@test.com", nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if capturedID != expectedID {
		t.Errorf("expected userID %q in context, got %q", expectedID, capturedID)
	}
}

func TestRequirePermission_Granted(t *testing.T) {
	next := http.HandlerFunc(okHandler)
	handler := RequirePermission("read:users")(next)

	ctx := context.WithValue(context.Background(), contextKey("permissions"), []string{"read:users", "manage:roles"})
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestRequirePermission_Denied(t *testing.T) {
	next := http.HandlerFunc(okHandler)
	handler := RequirePermission("manage:roles")(next)

	ctx := context.WithValue(context.Background(), contextKey("permissions"), []string{"read:users"})
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestRequirePermission_NoPermissionsInContext(t *testing.T) {
	next := http.HandlerFunc(okHandler)
	handler := RequirePermission("read:users")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}
