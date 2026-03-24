package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/nayan-labs/zapauth/internal/auth"
	"github.com/nayan-labs/zapauth/internal/config"
	"github.com/nayan-labs/zapauth/internal/email"
	"github.com/nayan-labs/zapauth/internal/middleware"
	"github.com/nayan-labs/zapauth/internal/token"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func Execute() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "init":
		runInit()
	case "start":
		runStart()
	case "generate-secret":
		runGenerateSecret()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("ZapAuth CLI")
	fmt.Println("Usage:")
	fmt.Println("  zapauth init            -> Initialize config and database migrations")
	fmt.Println("  zapauth start           -> Start the authentication server")
	fmt.Println("  zapauth generate-secret -> Generate a secure JWT secret")
}

func ensureDatabaseExists(dsn string) {
	if !strings.Contains(dsn, "dbname=") {
		return
	}

	// Swap chosen dbname with 'postgres' (the default postgres system db)
	parts := strings.Split(dsn, " ")
	defaultDSN := ""
	dbName := ""
	for _, p := range parts {
		if strings.HasPrefix(p, "dbname=") {
			dbName = strings.TrimPrefix(p, "dbname=")
			defaultDSN += "dbname=postgres "
		} else {
			defaultDSN += p + " "
		}
	}

	db, err := gorm.Open(postgres.Open(defaultDSN), &gorm.Config{})
	if err != nil {
		return // Silently fail, let the main connection catch and report the error
	}
	sqlDB, _ := db.DB()
	if sqlDB != nil {
		defer sqlDB.Close()
	}

	var count int64
	db.Raw("SELECT count(*) FROM pg_database WHERE datname = ?", dbName).Scan(&count)
	if count == 0 {
		fmt.Printf("⚡ Database '%s' does not exist. Creating it automatically for true zero-config!\n", dbName)
		db.Exec(fmt.Sprintf("CREATE DATABASE %s;", dbName))
	}
}

func runInit() {
	cfg := config.LoadConfig()
	
	// Create the DB automatically if missing
	ensureDatabaseExists(cfg.DBDsn)

	db, err := gorm.Open(postgres.Open(cfg.DBDsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	fmt.Println("Running database migrations...")
	err = db.AutoMigrate(&auth.User{}, &auth.Session{}, &auth.MagicLinkToken{})
	if err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	fmt.Println("Initialization complete. Database is ready.")
}

func runStart() {
	cfg := config.LoadConfig()
	
	// Ensure DB exists before starting
	ensureDatabaseExists(cfg.DBDsn)

	app := fiber.New(fiber.Config{
		AppName: "ZapAuth",
	})

	// Middlewares
	app.Use(middleware.NewLogger())
	app.Use(middleware.NewRateLimiter())

	// Database Setup
	db, err := gorm.Open(postgres.Open(cfg.DBDsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Database connection failed: %v", err)
	}

	// Dependencies
	repo := auth.NewRepository(db)
	tokenService := token.NewService(cfg)
	emailService := email.NewSMTPService(cfg)
	authService := auth.NewService(repo, tokenService, emailService)
	authHandler := auth.NewHandler(authService)

	jwtMiddleware := middleware.NewAuthMiddleware(tokenService)

	// Routes
	authHandler.RegisterRoutes(app, jwtMiddleware)

	// Health Check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Start server
	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("Starting ZapAuth server on %s", addr)
	if err := app.Listen(addr); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func runGenerateSecret() {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatalf("Failed to generate secret: %v", err)
	}
	secret := hex.EncodeToString(b)
	fmt.Printf("Generated Secret: %s\n", secret)
}
