# ZapAuth

ZapAuth is a clean, dependency-light, zero-configuration authentication system and library for Go applications. It provides production-ready JSON Web Token (JWT) management, Magic Link email logins, and robust middleware that can be integrated into any Go project instantly.

> [!IMPORTANT]
> This project is currently under active development. The API and features are subject to change.
> This project is not ready for production use, it's a work in progress.

## Architecture

ZapAuth is built natively on Go 1.26.0 and uses the Fiber web framework. It uses PostgreSQL as its data store via GORM and encrypts credentials securely. 

The project structure is split into two primary consumers:
1. **The Auth Server**: A standalone authentication microservice that issues JWTs and handles Magic Link flows.
2. **The Client Package**: A lightweight Go package (`github.com/nayan-labs/zapauth/pkg/zapauth`) built for other microservices to ingest ZapAuth JWTs and secure their own routes.

## Quickstart

### 1. Configuration

Clone the repository and prepare your environment:

```txt
git clone https://github.com/nayan-labs/zapauth.git
cd zapauth
cp .env.example .env
```

Ensure your `DB_DSN` is configured correctly inside your `.env` file to point to your PostgreSQL instance. 

### 2. CLI Usage

ZapAuth comes with a built-in command line interface to automate the entire lifecycle. You can run all commands directly via `go run cmd/server/main.go <command>`.

#### Initialize Database

```txt
go run cmd/server/main.go init
```
This command automatically connects to your PostgreSQL instance, creates the `zapauth` database if it does not already exist, and runs GORM auto-migrations to lay out the User, Session, and MagicLinkToken structures.

#### Start Server

```txt
go run cmd/server/main.go start
```
Starts the Fiber application. By default, the server binds to port 3000. ZapAuth includes automatic logging and rate-limiting middleware out of the box.

#### Generate JWT Secrets

```txt
go run cmd/server/main.go generate-secret
```
Generates a secure, 256-bit hexadecimal string. Copy this string into your `.env` file as your `JWT_SECRET` and `JWT_REFRESH_SECRET` for production workloads.

## Endpoints

Once running, the following endpoints evaluate the core authentication flows:

### Account Maintenance
- `POST /auth/signup` - Body: `{"email": "...", "password": "..."}`. Returns an Access and Refresh token.
- `POST /auth/login` - Body: `{"email": "...", "password": "..."}`. Returns an Access and Refresh token.
- `POST /auth/refresh` - Body: `{"refresh_token": "..."}`. Issues a new token pair.
- `POST /auth/logout` - Requires Auth Header. Revokes the session.
- `GET /auth/me` - Requires Auth Header. Returns the identity of the user.

### Magic Link Passwordless Flow
- `POST /auth/magic-link` - Body: `{"email": "..."}`. Triggers a secure URL dynamically generated and routed through SMTP. 
- `GET /auth/verify?token=...` - Consumes the magic link out of the email body and natively authenticates the user.

## Go Package Integration

You can protect your own secondary Go services by utilizing ZapAuth's native token validation middleware. Assuming the remote application shares the same `JWT_SECRET` configured in your authentication service:

```go
package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/nayan-labs/zapauth/pkg/zapauth"
)

func main() {
	app := fiber.New()

	// Initialize the middleware using your shared ZapAuth secret
	authMiddleware := zapauth.RequireAuth("super_secret_key_change_me")

	// Apply to protected routes
	protected := app.Group("/api", authMiddleware)
	protected.Get("/secure-data", func(c *fiber.Ctx) error {
		userID := c.Locals("user_id") // Automatically extracted from the validated JWT
		return c.JSON(fiber.Map{"user_id": userID, "status": "authorized"})
	})

	log.Fatal(app.Listen(":4000"))
}
```

See the `examples/basic-app/main.go` file for a practical implementation example.
