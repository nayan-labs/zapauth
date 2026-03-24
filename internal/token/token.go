package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nayan-labs/zapauth/internal/config"
)

type Service struct {
	cfg *config.Config
}

func NewService(cfg *config.Config) *Service {
	return &Service{cfg: cfg}
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

func (s *Service) GenerateTokenPair(userID string) (*TokenPair, error) {
	// Access Token
	accessClaims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(s.cfg.JWTAccessExpiry).Unix(),
		"iat": time.Now().Unix(),
		"typ": "access",
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessStr, err := accessToken.SignedString([]byte(s.cfg.JWTSecret))
	if err != nil {
		return nil, err
	}

	// Refresh Token
	refreshClaims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(s.cfg.JWTRefreshExpiry).Unix(),
		"iat": time.Now().Unix(),
		"typ": "refresh",
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshStr, err := refreshToken.SignedString([]byte(s.cfg.JWTRefreshSecret))
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessStr,
		RefreshToken: refreshStr,
	}, nil
}

func (s *Service) ValidateAccessToken(tokenStr string) (string, error) {
	return s.validateToken(tokenStr, s.cfg.JWTSecret, "access")
}

func (s *Service) ValidateRefreshToken(tokenStr string) (string, error) {
	return s.validateToken(tokenStr, s.cfg.JWTRefreshSecret, "refresh")
}

func (s *Service) validateToken(tokenStr, secret, tokenType string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})

	if err != nil || !token.Valid {
		return "", errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	typ, ok := claims["typ"].(string)
	if !ok || typ != tokenType {
		return "", errors.New("invalid token type")
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return "", errors.New("missing subject in token")
	}

	return sub, nil
}
