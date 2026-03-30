package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httprate"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/magomzr/go-iam-service/config"
	"github.com/magomzr/go-iam-service/internal/auth"
	internaldb "github.com/magomzr/go-iam-service/internal/db"
	"github.com/magomzr/go-iam-service/internal/db/sqlcgen"
	"github.com/magomzr/go-iam-service/internal/roles"
	"github.com/magomzr/go-iam-service/internal/token"
)

func main() {
	// Logger
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// Config
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("loading config")
	}

	if cfg.Env == "production" {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// DB pool
	ctx := context.Background()
	pool, err := internaldb.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("connecting to database")
	}
	defer pool.Close()

	// Limpieza periódica de refresh tokens expirados
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		q := sqlcgen.New(pool)
		for range ticker.C {
			if err := q.DeleteExpiredTokens(context.Background()); err != nil {
				log.Error().Err(err).Msg("cleaning expired tokens")
			} else {
				log.Info().Msg("expired refresh tokens cleaned")
			}
		}
	}()

	// Migraciones automáticas al arrancar
	sqlDB, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("opening sql db for migrations")
	}
	if err := goose.SetDialect("postgres"); err != nil {
		log.Fatal().Err(err).Msg("setting goose dialect")
	}
	if err := goose.Up(sqlDB, "db/migrations"); err != nil {
		log.Fatal().Err(err).Msg("running migrations")
	}
	sqlDB.Close()

	// Token manager
	tm, err := token.NewManager(
		cfg.JWTPrivateKeyPath,
		cfg.JWTPublicKeyPath,
		cfg.JWTKeyID,
		time.Duration(cfg.AccessTokenMinutes)*time.Minute,
		time.Duration(cfg.RefreshTokenDays)*24*time.Hour,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("initializing token manager")
	}

	// Services y handlers
	refreshTTL := time.Duration(cfg.RefreshTokenDays) * 24 * time.Hour
	authService := auth.NewService(pool, tm, refreshTTL)
	authHandler := auth.NewHandler(authService, tm)

	rolesService := roles.NewService(pool)
	rolesHandler := roles.NewHandler(rolesService)

	// Router
	r := chi.NewRouter()

	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.CORSOriginsList(),
		AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Rutas públicas con rate limiting
	r.Group(func(r chi.Router) {
		r.Use(httprate.LimitByIP(cfg.RateLimitRequests, time.Duration(cfg.RateLimitWindowS)*time.Second))
		r.Post("/auth/register", authHandler.Register)
		r.Post("/auth/login", authHandler.Login)
		r.Post("/auth/refresh", authHandler.Refresh)
		r.Get("/auth/jwks", authHandler.JWKS)
	})

	// Rutas autenticadas
	r.Group(func(r chi.Router) {
		r.Use(auth.RequireAuth(tm))
		r.Post("/auth/logout", authHandler.Logout)
		r.Post("/auth/change-password", authHandler.ChangePassword)
	})

	// Rutas admin
	r.Group(func(r chi.Router) {
		r.Use(auth.RequireAuth(tm))
		r.Use(auth.RequirePermission("manage:roles"))

		r.Get("/admin/roles", rolesHandler.ListRoles)
		r.Post("/admin/roles", rolesHandler.CreateRole)
		r.Delete("/admin/roles/{id}", rolesHandler.DeleteRole)
		r.Post("/admin/roles/{id}/permissions", rolesHandler.AssignPermissionToRole)
		r.Delete("/admin/roles/{id}/permissions/{pid}", rolesHandler.RevokePermissionFromRole)

		r.Get("/admin/permissions", rolesHandler.ListPermissions)
		r.Post("/admin/permissions", rolesHandler.CreatePermission)
		r.Delete("/admin/permissions/{id}", rolesHandler.DeletePermission)

		r.Get("/admin/users", rolesHandler.ListUsers)
		r.Post("/admin/users/{id}/roles", rolesHandler.AssignRoleToUser)
		r.Delete("/admin/users/{id}/roles/{rid}", rolesHandler.RevokeRoleFromUser)
	})

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	})

	// Servidor con graceful shutdown
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Info().Str("port", cfg.Port).Str("env", cfg.Env).Msg("server started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	log.Info().Msg("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatal().Err(err).Msg("forced shutdown")
	}

	log.Info().Msg("server stopped")
}
