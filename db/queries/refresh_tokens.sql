-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (user_id, token_hash, family, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetRefreshTokenByHash :one
SELECT * FROM refresh_tokens
WHERE token_hash = $1
LIMIT 1;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked = true
WHERE id = $1;

-- name: RevokeTokenFamily :exec
UPDATE refresh_tokens
SET revoked = true
WHERE family = $1;

-- name: RevokeAllUserTokens :exec
UPDATE refresh_tokens
SET revoked = true
WHERE user_id = $1 AND revoked = false;

-- name: DeleteExpiredTokens :exec
DELETE FROM refresh_tokens
WHERE expires_at < now();
