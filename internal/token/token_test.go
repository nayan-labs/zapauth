package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/nayan-labs/zapauth/internal/config"
)

func TestGenerateAndValidateToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:        "secret",
		JWTRefreshSecret: "refresh_secret",
		JWTAccessExpiry:  15 * time.Minute,
		JWTRefreshExpiry: 24 * time.Hour,
	}

	svc := NewService(cfg)
	userID := "123e4567-e89b-12d3-a456-426614174000"

	// 1. Generate
	tokens, err := svc.GenerateTokenPair(userID)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)

	// 2. Validate Access Token
	sub, err := svc.ValidateAccessToken(tokens.AccessToken)
	assert.NoError(t, err)
	assert.Equal(t, userID, sub)

	// 3. Validate Refresh Token
	subRefresh, err := svc.ValidateRefreshToken(tokens.RefreshToken)
	assert.NoError(t, err)
	assert.Equal(t, userID, subRefresh)
	
	// 4. Validate Bad Token
	_, err = svc.ValidateAccessToken("invalid.token.string")
	assert.Error(t, err)
}
