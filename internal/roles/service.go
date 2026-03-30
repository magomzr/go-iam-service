package roles

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/magomzr/go-iam-service/internal/db/sqlcgen"
	"github.com/magomzr/go-iam-service/internal/pghelper"
)

var ErrLastAdmin = errors.New("cannot remove the last active admin")

type Service struct {
	queries *sqlcgen.Queries
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{queries: sqlcgen.New(pool)}
}

func (s *Service) ListRoles(ctx context.Context) ([]sqlcgen.Role, error) {
	return s.queries.ListRoles(ctx)
}

func (s *Service) CreateRole(ctx context.Context, name string, description *string) (sqlcgen.Role, error) {
	return s.queries.CreateRole(ctx, sqlcgen.CreateRoleParams{
		Name:        name,
		Description: description,
	})
}

func (s *Service) DeleteRole(ctx context.Context, id uuid.UUID) error {
	return s.queries.DeleteRole(ctx, pghelper.UUID(id))
}

func (s *Service) ListPermissions(ctx context.Context) ([]sqlcgen.Permission, error) {
	return s.queries.ListPermissions(ctx)
}

func (s *Service) CreatePermission(ctx context.Context, action, resource string) (sqlcgen.Permission, error) {
	return s.queries.CreatePermission(ctx, sqlcgen.CreatePermissionParams{
		Action:   action,
		Resource: resource,
	})
}

func (s *Service) DeletePermission(ctx context.Context, id uuid.UUID) error {
	return s.queries.DeletePermission(ctx, pghelper.UUID(id))
}

func (s *Service) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	return s.queries.AssignPermissionToRole(ctx, sqlcgen.AssignPermissionToRoleParams{
		RoleID:       pghelper.UUID(roleID),
		PermissionID: pghelper.UUID(permissionID),
	})
}

func (s *Service) RevokePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	return s.queries.RevokePermissionFromRole(ctx, sqlcgen.RevokePermissionFromRoleParams{
		RoleID:       pghelper.UUID(roleID),
		PermissionID: pghelper.UUID(permissionID),
	})
}

func (s *Service) ListRolePermissions(ctx context.Context, roleID uuid.UUID) ([]sqlcgen.Permission, error) {
	return s.queries.ListRolePermissions(ctx, pghelper.UUID(roleID))
}

func (s *Service) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error {
	return s.queries.AssignRoleToUser(ctx, sqlcgen.AssignRoleToUserParams{
		UserID: pghelper.UUID(userID),
		RoleID: pghelper.UUID(roleID),
	})
}

func (s *Service) RevokeRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	role, err := s.queries.GetRoleByID(ctx, pghelper.UUID(roleID))
	if err != nil {
		return fmt.Errorf("fetching role: %w", err)
	}
	if role.Name == "admin" {
		count, err := s.queries.CountActiveAdmins(ctx)
		if err != nil {
			return fmt.Errorf("counting active admins: %w", err)
		}
		if count <= 1 {
			return ErrLastAdmin
		}
	}
	return s.queries.RevokeRoleFromUser(ctx, sqlcgen.RevokeRoleFromUserParams{
		UserID: pghelper.UUID(userID),
		RoleID: pghelper.UUID(roleID),
	})
}

func (s *Service) ListUsers(ctx context.Context) ([]sqlcgen.ListUsersRow, error) {
	return s.queries.ListUsers(ctx)
}

func (s *Service) ListUserRoles(ctx context.Context, userID uuid.UUID) ([]sqlcgen.Role, error) {
	return s.queries.ListUserRoles(ctx, pghelper.UUID(userID))
}

func (s *Service) DeactivateUser(ctx context.Context, id uuid.UUID) error {
	count, err := s.queries.CountActiveAdmins(ctx)
	if err != nil {
		return fmt.Errorf("counting active admins: %w", err)
	}
	if count <= 1 {
		roles, err := s.queries.ListUserRoles(ctx, pghelper.UUID(id))
		if err != nil {
			return fmt.Errorf("listing user roles: %w", err)
		}
		for _, r := range roles {
			if r.Name == "admin" {
				return ErrLastAdmin
			}
		}
	}
	return s.queries.DeactivateUser(ctx, pghelper.UUID(id))
}

func (s *Service) ActivateUser(ctx context.Context, id uuid.UUID) error {
	return s.queries.ActivateUser(ctx, pghelper.UUID(id))
}

func parseUUID(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("invalid uuid %q: %w", s, err)
	}
	return id, nil
}
