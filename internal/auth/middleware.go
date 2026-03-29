package auth

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/magomzr/go-iam-service/internal/token"
)

type contextKey string

const ctxKeyUserID contextKey = "userID"

func RequireAuth(tm *token.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				respondError(w, http.StatusUnauthorized, "missing authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				respondError(w, http.StatusUnauthorized, "invalid authorization header format")
				return
			}

			claims, err := tm.VerifyAccessToken(parts[1])
			if err != nil {
				respondError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			userID, err := uuid.Parse(claims.Subject)
			if err != nil {
				respondError(w, http.StatusUnauthorized, "invalid token subject")
				return
			}

			ctx := context.WithValue(r.Context(), ctxKeyUserID, userID)
			ctx = context.WithValue(ctx, contextKey("permissions"), claims.Permissions)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			perms, ok := r.Context().Value(contextKey("permissions")).([]string)
			if !ok {
				respondError(w, http.StatusForbidden, "forbidden")
				return
			}

			if slices.Contains(perms, permission) {
				next.ServeHTTP(w, r)
				return
			}

			respondError(w, http.StatusForbidden, "insufficient permissions")
		})
	}
}

func userIDFromCtx(r *http.Request) uuid.UUID {
	userID, _ := r.Context().Value(ctxKeyUserID).(uuid.UUID)
	return userID
}
