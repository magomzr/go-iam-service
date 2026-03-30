package roles

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

const maxBodyBytes = 1 << 20 // 1 MB

const errInvalidPermissionID = "invalid permission id"

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// GET /admin/roles
func (h *Handler) ListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.service.ListRoles(r.Context())
	if err != nil {
		log.Error().Err(err).Msg("list roles")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondJSON(w, http.StatusOK, roles)
}

// POST /admin/roles
func (h *Handler) CreateRole(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var body struct {
		Name        string  `json:"name"`
		Description *string `json:"description"`
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || body.Name == "" {
		respondError(w, http.StatusBadRequest, "name is required")
		return
	}

	if len(body.Name) > 64 {
		respondError(w, http.StatusBadRequest, "name must be 64 characters or fewer")
		return
	}

	role, err := h.service.CreateRole(r.Context(), body.Name, body.Description)
	if err != nil {
		log.Error().Err(err).Msg("create role")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondJSON(w, http.StatusCreated, role)
}

// DELETE /admin/roles/:id
func (h *Handler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid role id")
		return
	}

	if err := h.service.DeleteRole(r.Context(), id); err != nil {
		log.Error().Err(err).Msg("delete role")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /admin/permissions
func (h *Handler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := h.service.ListPermissions(r.Context())
	if err != nil {
		log.Error().Err(err).Msg("list permissions")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondJSON(w, http.StatusOK, perms)
}

// POST /admin/permissions
func (h *Handler) CreatePermission(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var body struct {
		Action   string `json:"action"`
		Resource string `json:"resource"`
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || body.Action == "" || body.Resource == "" {
		respondError(w, http.StatusBadRequest, "action and resource are required")
		return
	}

	if len(body.Action) > 64 || len(body.Resource) > 64 {
		respondError(w, http.StatusBadRequest, "action and resource must be 64 characters or fewer")
		return
	}

	perm, err := h.service.CreatePermission(r.Context(), body.Action, body.Resource)
	if err != nil {
		log.Error().Err(err).Msg("create permission")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondJSON(w, http.StatusCreated, perm)
}

// DELETE /admin/permissions/:id
func (h *Handler) DeletePermission(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, errInvalidPermissionID)
		return
	}

	if err := h.service.DeletePermission(r.Context(), id); err != nil {
		log.Error().Err(err).Msg("delete permission")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /admin/roles/:id/permissions
func (h *Handler) ListRolePermissions(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid role id")
		return
	}

	perms, err := h.service.ListRolePermissions(r.Context(), id)
	if err != nil {
		log.Error().Err(err).Msg("list role permissions")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondJSON(w, http.StatusOK, perms)
}

// POST /admin/roles/:id/permissions
func (h *Handler) AssignPermissionToRole(w http.ResponseWriter, r *http.Request) {
	roleID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid role id")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body struct {
		PermissionID string `json:"permission_id"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || body.PermissionID == "" {
		respondError(w, http.StatusBadRequest, "permission_id is required")
		return
	}

	permID, err := parseUUID(body.PermissionID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid permission id")
		return
	}

	if err := h.service.AssignPermissionToRole(r.Context(), roleID, permID); err != nil {
		log.Error().Err(err).Msg("assign permission to role")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DELETE /admin/roles/:id/permissions/:pid
func (h *Handler) RevokePermissionFromRole(w http.ResponseWriter, r *http.Request) {
	roleID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid role id")
		return
	}

	permID, err := parseUUID(chi.URLParam(r, "pid"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid permission id")
		return
	}

	if err := h.service.RevokePermissionFromRole(r.Context(), roleID, permID); err != nil {
		log.Error().Err(err).Msg("revoke permission from role")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /admin/users
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := h.service.ListUsers(r.Context())
	if err != nil {
		log.Error().Err(err).Msg("list users")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	type roleItem struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	type userItem struct {
		ID        any        `json:"id"`
		Email     string     `json:"email"`
		IsActive  bool       `json:"is_active"`
		CreatedAt any        `json:"created_at"`
		UpdatedAt any        `json:"updated_at"`
		Roles     []roleItem `json:"roles"`
	}

	result := make([]userItem, 0, len(rows))
	for _, u := range rows {
		var roles []roleItem
		if err := json.Unmarshal(u.Roles, &roles); err != nil {
			roles = []roleItem{}
		}
		result = append(result, userItem{
			ID:        u.ID,
			Email:     u.Email,
			IsActive:  u.IsActive,
			CreatedAt: u.CreatedAt,
			UpdatedAt: u.UpdatedAt,
			Roles:     roles,
		})
	}
	respondJSON(w, http.StatusOK, result)
}

// GET /admin/users/:id/roles
func (h *Handler) ListUserRoles(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	roles, err := h.service.ListUserRoles(r.Context(), id)
	if err != nil {
		log.Error().Err(err).Msg("list user roles")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondJSON(w, http.StatusOK, roles)
}

// PATCH /admin/users/:id/deactivate
func (h *Handler) DeactivateUser(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	if err := h.service.DeactivateUser(r.Context(), id); err != nil {
		if errors.Is(err, ErrLastAdmin) {
			respondError(w, http.StatusConflict, "cannot deactivate the last active admin")
			return
		}
		log.Error().Err(err).Msg("deactivate user")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PATCH /admin/users/:id/activate
func (h *Handler) ActivateUser(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	if err := h.service.ActivateUser(r.Context(), id); err != nil {
		log.Error().Err(err).Msg("activate user")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /admin/users/:id/roles
func (h *Handler) AssignRoleToUser(w http.ResponseWriter, r *http.Request) {
	userID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body struct {
		RoleID string `json:"role_id"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || body.RoleID == "" {
		respondError(w, http.StatusBadRequest, "role_id is required")
		return
	}

	roleID, err := parseUUID(body.RoleID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid role id")
		return
	}

	if err := h.service.AssignRoleToUser(r.Context(), userID, roleID); err != nil {
		log.Error().Err(err).Msg("assign role to user")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DELETE /admin/users/:id/roles/:rid
func (h *Handler) RevokeRoleFromUser(w http.ResponseWriter, r *http.Request) {
	userID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	roleID, err := parseUUID(chi.URLParam(r, "rid"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid role id")
		return
	}

	if err := h.service.RevokeRoleFromUser(r.Context(), userID, roleID); err != nil {
		if errors.Is(err, ErrLastAdmin) {
			respondError(w, http.StatusConflict, "cannot remove the last active admin")
			return
		}
		log.Error().Err(err).Msg("revoke role from user")
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func respondJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}
