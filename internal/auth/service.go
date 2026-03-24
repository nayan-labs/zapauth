package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/nayan-labs/zapauth/internal/email"
	"github.com/nayan-labs/zapauth/internal/token"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Service interface {
	Signup(ctx context.Context, req *SignupReq) (*token.TokenPair, error)
	Login(ctx context.Context, req *LoginReq) (*token.TokenPair, error)
	Logout(ctx context.Context, refreshToken string) error
	Refresh(ctx context.Context, refreshToken string) (*token.TokenPair, error)
	GetMe(ctx context.Context, userID string) (*UserResponse, error)

	RequestMagicLink(ctx context.Context, req *MagicLinkReq) error
	VerifyMagicLink(ctx context.Context, req *VerifyMagicLinkReq) (*token.TokenPair, error)
}

type authService struct {
	repo         Repository
	tokenService *token.Service
	emailService email.Service
}

func NewService(repo Repository, tokenService *token.Service, emailService email.Service) Service {
	return &authService{
		repo:         repo,
		tokenService: tokenService,
		emailService: emailService,
	}
}

// Request models

type SignupReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

type MagicLinkReq struct {
	Email string `json:"email"`
}

type VerifyMagicLinkReq struct {
	Token string `json:"token"`
}

type UserResponse struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *authService) Signup(ctx context.Context, req *SignupReq) (*token.TokenPair, error) {
	_, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err == nil {
		return nil, errors.New("email already in use")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &User{
		Email:        req.Email,
		PasswordHash: string(hash),
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	return s.createSession(ctx, user.ID.String())
}

func (s *authService) Login(ctx context.Context, req *LoginReq) (*token.TokenPair, error) {
	user, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	return s.createSession(ctx, user.ID.String())
}

func (s *authService) Logout(ctx context.Context, refreshToken string) error {
	return s.repo.DeleteSession(ctx, refreshToken)
}

func (s *authService) Refresh(ctx context.Context, refreshToken string) (*token.TokenPair, error) {
	// Validate token cryptographic signature First
	userIDStr, err := s.tokenService.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Verify token is in DB
	session, err := s.repo.GetSessionByToken(ctx, refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	if time.Now().After(session.ExpiresAt) {
		_ = s.repo.DeleteSession(ctx, refreshToken)
		return nil, errors.New("refresh token expired")
	}

	// Invalidate old token and create new one
	_ = s.repo.DeleteSession(ctx, refreshToken)

	return s.createSession(ctx, userIDStr)
}

func (s *authService) GetMe(ctx context.Context, userID string) (*UserResponse, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &UserResponse{
		ID:        user.ID.String(),
		Email:     user.Email,
		Verified:  user.Verified,
		CreatedAt: user.CreatedAt,
	}, nil
}

func (s *authService) RequestMagicLink(ctx context.Context, req *MagicLinkReq) error {
	user, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		// If user doesn't exist, you might choose to create them here as verified=false 
		// or return nil to avoid email enumeration. We'll implicitly create them for seamless "magic" login.
		if errors.Is(err, gorm.ErrRecordNotFound) {
			user = &User{
				Email:        req.Email,
				PasswordHash: "", // No password
				Verified:     false,
			}
			if err := s.repo.CreateUser(ctx, user); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	// Create magic link token (secure string)
	b := make([]byte, 32)
	rand.Read(b)
	secureToken := hex.EncodeToString(b)

	ml := &MagicLinkToken{
		Email:     req.Email,
		Token:     secureToken,
		ExpiresAt: time.Now().Add(15 * time.Minute), // Link valid for 15m
	}

	if err := s.repo.CreateMagicLink(ctx, ml); err != nil {
		return err
	}

	return s.emailService.SendMagicLink(req.Email, secureToken)
}

func (s *authService) VerifyMagicLink(ctx context.Context, req *VerifyMagicLinkReq) (*token.TokenPair, error) {
	ml, err := s.repo.GetMagicLink(ctx, req.Token)
	if err != nil {
		return nil, errors.New("invalid or expired magic link")
	}

	if time.Now().After(ml.ExpiresAt) {
		_ = s.repo.DeleteMagicLink(ctx, req.Token)
		return nil, errors.New("magic link expired")
	}

	user, err := s.repo.GetUserByEmail(ctx, ml.Email)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Optional: mark verified if they aren't
	if !user.Verified {
		user.Verified = true
		_ = s.repo.UpdateUser(ctx, user)
	}

	// Burn token
	_ = s.repo.DeleteMagicLink(ctx, req.Token)

	return s.createSession(ctx, user.ID.String())
}

func (s *authService) createSession(ctx context.Context, userIDStr string) (*token.TokenPair, error) {
	tokens, err := s.tokenService.GenerateTokenPair(userIDStr)
	if err != nil {
		return nil, err
	}

	uID, _ := uuid.Parse(userIDStr)
	// Add session to DB
	session := &Session{
		UserID:       uID,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    time.Now().Add(24 * 7 * time.Hour), // Will sync with config ideally
	}
	
	if err := s.repo.CreateSession(ctx, session); err != nil {
		return nil, err
	}

	return tokens, nil
}
