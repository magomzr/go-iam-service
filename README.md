# go-iam-service

Servicio de autenticación e identidad (IAM) escrito en Go. Emite JWTs firmados con RS256 con permisos RBAC embebidos en formato `action:resource`, diseñado para ser consumido por múltiples servicios backend.

Proyecto portfolio — construido para aprender Go idiomático y arquitectura de servicios de autenticación seguros.

## Arquitectura

```
Cliente (Angular / curl)
    │
    ├── POST /auth/login ──────────────► go-iam-service
    │                                        │ verifica password (Argon2id)
    │                                        │ consulta permisos del usuario
    │                                        │ firma JWT RS256
    │◄── { access_token, refresh_token } ────┘
    │
    ├── GET /api/resource ────────────► NestJS API (u otro servicio)
    │   Authorization: Bearer <jwt>        │ verifica firma con clave pública
    │                                      │ extrae permissions[] del payload
    │◄── 200 OK ───────────────────────────┘ sin tocar la DB
```

## Stack

| Concern | Librería |
|---|---|
| Router | `go-chi/chi v5` |
| Base de datos | `jackc/pgx v5` + `pgxpool` |
| Queries tipadas | `sqlc` |
| JWT | `golang-jwt/jwt v5` — RS256 |
| Password hashing | `golang.org/x/crypto/argon2` — Argon2id |
| Migraciones | `pressly/goose v3` |
| Config | `caarlos0/env v11` |
| Logging | `rs/zerolog` |
| Rate limiting | `go-chi/httprate` |

## Seguridad

| Área | Decisión |
|---|---|
| Password hashing | Argon2id — memory=64MB, iterations=3, parallelism=2 (mínimos OWASP 2024) |
| Algoritmo JWT | RS256 — asimétrico, la clave privada nunca sale del IAM |
| Refresh tokens | Almacenados como SHA-256 en DB, nunca en claro |
| Rotación | Cada uso del refresh token emite uno nuevo y revoca el anterior |
| Reutilización | Si se detecta un token ya rotado, se revoca la familia completa (sesión entera) |
| Rate limiting | Por IP en endpoints de auth |
| Enumeración | Login retorna el mismo error si el email no existe o si la password es incorrecta |
| Comparación | `subtle.ConstantTimeCompare` para evitar timing attacks |
| Clave privada | Nunca en el repositorio — se monta como secret en producción |

## Estructura del proyecto

```
go-iam-service/
├── cmd/server/
│   └── main.go                  # punto de entrada, wiring, graceful shutdown
├── config/
│   └── config.go                # variables de entorno tipadas
├── db/
│   ├── migrations/              # SQL con goose (Up/Down)
│   └── queries/                 # SQL para sqlc
├── internal/
│   ├── auth/
│   │   ├── handler.go           # handlers HTTP de auth
│   │   ├── middleware.go        # JWT middleware, RequirePermission
│   │   └── service.go           # lógica: register, login, refresh, logout, change-password
│   ├── db/
│   │   ├── db.go                # pgxpool setup
│   │   └── sqlcgen/             # código generado por sqlc — no editar
│   ├── pghelper/
│   │   └── pghelper.go          # conversores pgtype.UUID <-> uuid.UUID
│   ├── roles/
│   │   ├── handler.go           # handlers HTTP admin
│   │   └── service.go           # lógica: CRUD roles, permisos, asignaciones
│   └── token/
│       └── jwt.go               # sign/verify RS256, JWKS, HashToken
├── keys/
│   ├── private.pem              # NO commitear
│   └── public.pem               # publica — se puede compartir
├── scripts/
│   └── gen-keys.sh              # genera el par RSA
├── Containerfile                # multistage build
├── compose.yml
├── sqlc.yaml
└── go.mod
```

## Setup local

### 1. Generar claves RSA

```bash
chmod +x scripts/gen-keys.sh
./scripts/gen-keys.sh
```

Genera `keys/private.pem` y `keys/public.pem`. La clave privada está en `.gitignore`.

### 2. Variables de entorno

Crea un archivo `.env` en la raíz:

```env
PORT=8080
ENV=development
DATABASE_URL=postgres://iam:iam_secret@localhost:5432/iam_db?sslmode=disable
JWT_PRIVATE_KEY_PATH=keys/private.pem
JWT_PUBLIC_KEY_PATH=keys/public.pem
JWT_KEY_ID=v1
ACCESS_TOKEN_MINUTES=15
REFRESH_TOKEN_DAYS=7
RATE_LIMIT_REQUESTS=10
RATE_LIMIT_WINDOW_S=60
```

### 3. Levantar Postgres

```bash
podman run -d \
  --name iam-postgres \
  -e POSTGRES_USER=iam \
  -e POSTGRES_PASSWORD=iam_secret \
  -e POSTGRES_DB=iam_db \
  -p 5432:5432 \
  docker.io/library/postgres:17-alpine
```

### 4. Correr el servidor

```bash
export $(cat .env | xargs) && go run ./cmd/server
```

Las migraciones corren automáticamente al arrancar.

### 5. Con Podman Compose

```bash
podman compose up --build
```

## Regenerar código sqlc

Si modificas algún archivo en `db/queries/` o `db/migrations/`:

```bash
sqlc generate
```

El código generado vive en `internal/db/sqlcgen/` — nunca editar manualmente.

## API

### Endpoints públicos (rate-limited: 10 req/min por IP)

```
POST /auth/register        { email, password }
POST /auth/login           { email, password } → { access_token, refresh_token, token_type }
POST /auth/refresh         { refresh_token }   → { access_token, refresh_token, token_type }
GET  /auth/jwks                               → JWKS con clave pública RS256
GET  /health
```

### Endpoints autenticados

```
POST /auth/logout          Authorization: Bearer <token>
POST /auth/change-password { current_password, new_password }
```

### Endpoints admin (requieren permiso manage:roles)

```
GET    /admin/roles
POST   /admin/roles                          { name, description? }
DELETE /admin/roles/:id

GET    /admin/permissions
POST   /admin/permissions                    { action, resource }
DELETE /admin/permissions/:id

POST   /admin/roles/:id/permissions          { permission_id }
DELETE /admin/roles/:id/permissions/:pid

GET    /admin/users
POST   /admin/users/:id/roles                { role_id }
DELETE /admin/users/:id/roles/:rid
```

## Payload del JWT

```json
{
  "sub": "uuid-del-usuario",
  "email": "usuario@ejemplo.com",
  "permissions": [
    "read:users",
    "manage:roles",
    "create:posts"
  ],
  "iat": 1718000000,
  "exp": 1718000900,
  "jti": "uuid-unico"
}
```

- Access token TTL: **15 minutos**
- Refresh token TTL: **7 días**
- Los permisos viajan en el token — los servicios consumidores no necesitan ir a la DB para autorizar

## Consumir el IAM desde otro servicio

### NestJS con passport-jwt

```typescript
JwtModule.registerAsync({
  useFactory: async () => ({
    secretOrKeyProvider: passportJwtSecret({
      jwksUri: 'http://iam-service:8080/auth/jwks',
    }),
    verifyOptions: {
      algorithms: ['RS256'],
    },
  }),
})
```

Los permisos están disponibles directamente en el payload — sin llamada adicional a la DB.

### Verificación manual de la clave pública

```bash
# Obtener las claves públicas
curl http://localhost:8080/auth/jwks
```

O montar `keys/public.pem` directamente en el servicio consumidor.

## Bootstrap del primer admin

El seed crea el rol `admin` con todos los permisos, pero no asigna usuarios. Para el primer admin hay que hacerlo directamente en la DB:

```bash
podman exec -it iam-postgres psql -U iam -d iam_db -c "
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.email = 'tu@email.com'
AND r.name = 'admin';
"
```

Después de esto el usuario recibe un JWT con todos los permisos admin en el próximo login.

## Variables de entorno

| Variable | Default | Descripción |
|---|---|---|
| `PORT` | `8080` | Puerto HTTP |
| `ENV` | `development` | `development` o `production` |
| `DATABASE_URL` | requerido | Connection string de PostgreSQL |
| `JWT_PRIVATE_KEY_PATH` | `keys/private.pem` | Path a la clave RSA privada |
| `JWT_PUBLIC_KEY_PATH` | `keys/public.pem` | Path a la clave RSA pública |
| `JWT_KEY_ID` | `v1` | Key ID para rotación de claves (JWKS) |
| `ACCESS_TOKEN_MINUTES` | `15` | TTL del access token en minutos |
| `REFRESH_TOKEN_DAYS` | `7` | TTL del refresh token en días |
| `RATE_LIMIT_REQUESTS` | `10` | Máximo de requests por ventana |
| `RATE_LIMIT_WINDOW_S` | `60` | Ventana de rate limit en segundos |
