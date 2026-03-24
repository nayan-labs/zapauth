package auth

import (
	"context"

	"github.com/stretchr/testify/mock"
)

// MockRepository is a test utility matching auth.Repository
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) CreateUser(ctx context.Context, user *User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) != nil {
		return args.Get(0).(*User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockRepository) GetUserByID(ctx context.Context, id string) (*User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) != nil {
		return args.Get(0).(*User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockRepository) UpdateUser(ctx context.Context, user *User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockRepository) CreateSession(ctx context.Context, session *Session) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *MockRepository) GetSessionByToken(ctx context.Context, token string) (*Session, error) {
	args := m.Called(ctx, token)
	if args.Get(0) != nil {
		return args.Get(0).(*Session), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockRepository) DeleteSession(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockRepository) CreateMagicLink(ctx context.Context, MagicLinkToken *MagicLinkToken) error {
	args := m.Called(ctx, MagicLinkToken)
	return args.Error(0)
}

func (m *MockRepository) GetMagicLink(ctx context.Context, token string) (*MagicLinkToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) != nil {
		return args.Get(0).(*MagicLinkToken), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockRepository) DeleteMagicLink(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}
