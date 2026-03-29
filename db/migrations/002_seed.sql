-- +goose Up
-- +goose StatementBegin

INSERT INTO roles (id, name, description)
VALUES (gen_random_uuid(), 'admin', 'Full access to all resources');

INSERT INTO permissions (action, resource) VALUES
    ('manage', 'roles'),
    ('manage', 'permissions'),
    ('manage', 'users'),
    ('read',   'users'),
    ('create', 'users'),
    ('update', 'users'),
    ('delete', 'users');

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'admin';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM role_permissions
WHERE role_id = (SELECT id FROM roles WHERE name = 'admin');

DELETE FROM permissions
WHERE (action, resource) IN (
    ('manage', 'roles'), ('manage', 'permissions'), ('manage', 'users'),
    ('read', 'users'), ('create', 'users'), ('update', 'users'), ('delete', 'users')
);

DELETE FROM roles WHERE name = 'admin';

-- +goose StatementEnd
