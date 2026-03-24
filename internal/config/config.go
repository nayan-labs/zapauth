package config

import (
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Port             string
	DBDsn            string
	JWTSecret        string
	JWTRefreshSecret string
	JWTAccessExpiry  time.Duration
	JWTRefreshExpiry time.Duration
	SMTPHost         string
	SMTPPort         int
	SMTPUser         string
	SMTPPass         string
	SMTPFrom         string
}

func LoadConfig() *Config {
	_ = godotenv.Load() // ignore error, might be provided via env directly

	port := getEnv("PORT", "3000")
	dbDsn := getEnv("DB_DSN", "host=localhost user=postgres password=postgres dbname=zapauth port=5432 sslmode=disable TimeZone=UTC")
	
	accessExpiry, err := time.ParseDuration(getEnv("JWT_ACCESS_EXPIRY", "15m"))
	if err != nil {
		accessExpiry = 15 * time.Minute
	}
	refreshExpiry, err := time.ParseDuration(getEnv("JWT_REFRESH_EXPIRY", "168h"))
	if err != nil {
		refreshExpiry = 168 * time.Hour
	}

	smtpPort, err := strconv.Atoi(getEnv("SMTP_PORT", "2525"))
	if err != nil {
		smtpPort = 2525
	}

	return &Config{
		Port:             port,
		DBDsn:            dbDsn,
		JWTSecret:        getEnv("JWT_SECRET", "super_secret_key_change_me"),
		JWTRefreshSecret: getEnv("JWT_REFRESH_SECRET", "super_secret_refresh_key_change_me"),
		JWTAccessExpiry:  accessExpiry,
		JWTRefreshExpiry: refreshExpiry,
		SMTPHost:         getEnv("SMTP_HOST", "localhost"),
		SMTPPort:         smtpPort,
		SMTPUser:         getEnv("SMTP_USER", ""),
		SMTPPass:         getEnv("SMTP_PASS", ""),
		SMTPFrom:         getEnv("SMTP_FROM", "noreply@zapauth.local"),
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
