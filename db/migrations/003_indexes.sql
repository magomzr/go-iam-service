-- +goose Up
-- +goose StatementBegin

CREATE INDEX idx_users_email ON users(email);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_users_email;

-- +goose StatementEnd