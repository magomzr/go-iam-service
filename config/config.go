package config

import "github.com/caarlos0/env/v11"

type Config struct {
	// Server
	Port string `env:"PORT" envDefault:"8080"`
	Env  string `env:"ENV"  envDefault:"development"`

	// Database
	DatabaseURL string `env:"DATABASE_URL,required"`

	// JWT
	JWTPrivateKeyPath string `env:"JWT_PRIVATE_KEY_PATH" envDefault:"keys/private.pem"`
	JWTPublicKeyPath  string `env:"JWT_PUBLIC_KEY_PATH"  envDefault:"keys/public.pem"`
	JWTKeyID          string `env:"JWT_KEY_ID"           envDefault:"v1"`

	// Token durations
	AccessTokenMinutes int `env:"ACCESS_TOKEN_MINUTES" envDefault:"15"`
	RefreshTokenDays   int `env:"REFRESH_TOKEN_DAYS"   envDefault:"7"`

	// Rate limiting
	RateLimitRequests int `env:"RATE_LIMIT_REQUESTS" envDefault:"10"`
	RateLimitWindowS  int `env:"RATE_LIMIT_WINDOW_S"  envDefault:"60"`
}

func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
