package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"github.com/rs/zerolog/log"
)

const maxBodyBytes = 1 << 20 // 1 MB

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

type Handler struct {
	service      *Service
	tokenManager interface{ JWKS() map[string]any }
}

func NewHandler(service *Service, tm interface{ JWKS() map[string]any }) *Handler {
	return &Handler{service: service, tokenManager: tm}
}

// POST /auth/register
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.Email == "" || body.Password == "" {
		respondError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	if !emailRe.MatchString(body.Email) || len(body.Email) > 254 {
		respondError(w, http.StatusBadRequest, "invalid email")
		return
	}

	if len(body.Password) < 8 || len(body.Password) > 72 {
		respondError(w, http.StatusBadRequest, "password must be between 8 and 72 characters")
		return
	}

	if err := h.service.Register(r.Context(), body.Email, body.Password); err != nil {
		if errors.Is(err, ErrUserAlreadyExists) {
			respondError(w, http.StatusConflict, "email already registered")
			return
		}
		log.Error().Err(err).Msg("register error")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	respondJSON(w, http.StatusCreated, map[string]string{"message": "user created"})
}

// POST /auth/login
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	pair, err := h.service.Login(r.Context(), body.Email, body.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			respondError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		log.Error().Err(err).Msg("login error")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"access_token":  pair.AccessToken,
		"refresh_token": pair.RefreshToken,
		"token_type":    "Bearer",
	})
}

// POST /auth/refresh
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var body struct {
		RefreshToken string `json:"refresh_token"`
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || body.RefreshToken == "" {
		respondError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	if len(body.RefreshToken) > 128 {
		respondError(w, http.StatusBadRequest, "invalid refresh token")
		return
	}

	pair, err := h.service.Refresh(r.Context(), body.RefreshToken)
	if err != nil {
		if errors.Is(err, ErrTokenInvalid) || errors.Is(err, ErrTokenReused) {
			respondError(w, http.StatusUnauthorized, "invalid or expired refresh token")
			return
		}
		log.Error().Err(err).Msg("refresh error")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"access_token":  pair.AccessToken,
		"refresh_token": pair.RefreshToken,
		"token_type":    "Bearer",
	})
}

// POST /auth/logout
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromCtx(r)

	if err := h.service.Logout(r.Context(), userID); err != nil {
		log.Error().Err(err).Msg("logout error")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

// POST /auth/change-password
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(body.NewPassword) < 8 || len(body.NewPassword) > 72 {
		respondError(w, http.StatusBadRequest, "new password must be between 8 and 72 characters")
		return
	}

	userID := userIDFromCtx(r)

	if err := h.service.ChangePassword(r.Context(), userID, body.CurrentPassword, body.NewPassword); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			respondError(w, http.StatusUnauthorized, "current password is incorrect")
			return
		}
		log.Error().Err(err).Msg("change password error")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"message": "password updated — all sessions revoked"})
}

// GET /auth/jwks
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, h.tokenManager.JWKS())
}

// --- helpers ---

func respondJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}
