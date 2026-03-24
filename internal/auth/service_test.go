package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nayan-labs/zapauth/internal/config"
	"github.com/nayan-labs/zapauth/internal/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type mockEmailService struct {
	mock.Mock
}

func (m *mockEmailService) SendMagicLink(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

func TestSignup_Success(t *testing.T) {
	mockRepo := new(MockRepository)
	cfg := &config.Config{JWTSecret: "sec", JWTRefreshSecret: "rsec", JWTAccessExpiry: time.Hour, JWTRefreshExpiry: time.Hour}
	tokenSvc := token.NewService(cfg)
	svc := NewService(mockRepo, tokenSvc, nil)

	req := &SignupReq{
		Email:    "test@nayan.com",
		Password: "password123",
	}

	// 1. Verify user doesn't exist
	mockRepo.On("GetUserByEmail", mock.Anything, req.Email).Return(nil, gorm.ErrRecordNotFound)
	
	// 2. Create User
	mockRepo.On("CreateUser", mock.Anything, mock.AnythingOfType("*auth.User")).Return(nil)
	
	// 3. Create Session
	mockRepo.On("CreateSession", mock.Anything, mock.AnythingOfType("*auth.Session")).Return(nil)

	tokens, err := svc.Signup(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, tokens)
	assert.NotEmpty(t, tokens.AccessToken)

	mockRepo.AssertExpectations(t)
}

func TestLogin_Success(t *testing.T) {
	mockRepo := new(MockRepository)
	cfg := &config.Config{JWTSecret: "sec", JWTRefreshSecret: "rsec", JWTAccessExpiry: time.Hour, JWTRefreshExpiry: time.Hour}
	tokenSvc := token.NewService(cfg)
	svc := NewService(mockRepo, tokenSvc, nil)

	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)

	user := &User{
		ID:           uuid.New(),
		Email:        "test@nayan.com",
		PasswordHash: string(hash),
	}

	req := &LoginReq{
		Email:    "test@nayan.com",
		Password: "password123",
	}

	mockRepo.On("GetUserByEmail", mock.Anything, req.Email).Return(user, nil)
	mockRepo.On("CreateSession", mock.Anything, mock.AnythingOfType("*auth.Session")).Return(nil)

	tokens, err := svc.Login(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, tokens)

	mockRepo.AssertExpectations(t)
}

func TestLogin_InvalidCredentials(t *testing.T) {
	mockRepo := new(MockRepository)
	cfg := &config.Config{JWTSecret: "sec", JWTRefreshSecret: "rsec", JWTAccessExpiry: time.Hour, JWTRefreshExpiry: time.Hour}
	tokenSvc := token.NewService(cfg)
	svc := NewService(mockRepo, tokenSvc, nil)

	req := &LoginReq{
		Email:    "test@nayan.com",
		Password: "wrongpassword",
	}

	mockRepo.On("GetUserByEmail", mock.Anything, req.Email).Return(nil, gorm.ErrRecordNotFound)

	tokens, err := svc.Login(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, tokens)
	assert.Equal(t, "invalid credentials", err.Error())

	mockRepo.AssertExpectations(t)
}

func TestRequestMagicLink_Success(t *testing.T) {
	mockRepo := new(MockRepository)
	cfg := &config.Config{JWTSecret: "sec", JWTRefreshSecret: "rsec", JWTAccessExpiry: time.Hour, JWTRefreshExpiry: time.Hour}
	tokenSvc := token.NewService(cfg)
	
	mockEmail := new(mockEmailService)
	svc := NewService(mockRepo, tokenSvc, mockEmail)

	user := &User{ID: uuid.New(), Email: "test@nayan.com"}
	req := &MagicLinkReq{Email: "test@nayan.com"}

	mockRepo.On("GetUserByEmail", mock.Anything, req.Email).Return(user, nil)
	mockRepo.On("CreateMagicLink", mock.Anything, mock.AnythingOfType("*auth.MagicLinkToken")).Return(nil)
	mockEmail.On("SendMagicLink", req.Email, mock.AnythingOfType("string")).Return(nil)

	err := svc.RequestMagicLink(context.Background(), req)
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
	mockEmail.AssertExpectations(t)
}
