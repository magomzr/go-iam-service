-- name: CreateUser :one
INSERT INTO users (email, password)
VALUES ($1, $2)
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1 AND is_active = true
LIMIT 1;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1 AND is_active = true
LIMIT 1;

-- name: ListUsers :many
SELECT id, email, is_active, created_at, updated_at FROM users
ORDER BY created_at DESC;

-- name: UpdateUserPassword :one
UPDATE users
SET password = $2, updated_at = now()
WHERE id = $1
RETURNING *;

-- name: DeactivateUser :exec
UPDATE users
SET is_active = false, updated_at = now()
WHERE id = $1;

-- name: CountActiveAdmins :one
SELECT COUNT(*) FROM users u
JOIN user_roles ur ON ur.user_id = u.id
JOIN roles r ON r.id = ur.role_id
WHERE r.name = 'admin' AND u.is_active = true;

-- name: ActivateUser :exec
UPDATE users
SET is_active = true, updated_at = now()
WHERE id = $1;

-- name: GetUserPermissions :many
SELECT DISTINCT
    CAST(p.action || ':' || p.resource AS TEXT) AS permission
FROM users u
JOIN user_roles ur ON ur.user_id = u.id
JOIN role_permissions rp ON rp.role_id = ur.role_id
JOIN permissions p ON p.id = rp.permission_id
WHERE u.id = $1 AND u.is_active = true;
