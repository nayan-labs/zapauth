package zapauth

import (
	"github.com/gofiber/fiber/v2"
	"github.com/nayan-labs/zapauth/internal/config"
	"github.com/nayan-labs/zapauth/internal/middleware"
	"github.com/nayan-labs/zapauth/internal/token"
)

// RequireAuth returns a strict JWT middleware that extracts and validates ZapAuth access tokens
func RequireAuth(jwtSecret string) fiber.Handler {
	// For convenience, constructing a limited config here to reuse internal middleware
	cfg := &config.Config{
		JWTSecret: jwtSecret,
	}
	tokenService := token.NewService(cfg)
	return middleware.NewAuthMiddleware(tokenService)
}
