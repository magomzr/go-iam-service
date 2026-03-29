package roles

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/magomzr/go-iam-service/internal/db/sqlcgen"
	"github.com/magomzr/go-iam-service/internal/pghelper"
)

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
	return s.queries.RevokeRoleFromUser(ctx, sqlcgen.RevokeRoleFromUserParams{
		UserID: pghelper.UUID(userID),
		RoleID: pghelper.UUID(roleID),
	})
}

func (s *Service) ListUsers(ctx context.Context) ([]sqlcgen.ListUsersRow, error) {
	return s.queries.ListUsers(ctx)
}

func parseUUID(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("invalid uuid %q: %w", s, err)
	}
	return id, nil
}
