package auth

import (
	"context"

	"gorm.io/gorm"
)

type Repository interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByID(ctx context.Context, id string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error

	CreateSession(ctx context.Context, session *Session) error
	GetSessionByToken(ctx context.Context, token string) (*Session, error)
	DeleteSession(ctx context.Context, token string) error

	CreateMagicLink(ctx context.Context, token *MagicLinkToken) error
	GetMagicLink(ctx context.Context, token string) (*MagicLinkToken, error)
	DeleteMagicLink(ctx context.Context, token string) error
}

type repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) Repository {
	return &repository{db: db}
}

func (r *repository) CreateUser(ctx context.Context, user *User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *repository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *repository) GetUserByID(ctx context.Context, id string) (*User, error) {
	var user User
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *repository) UpdateUser(ctx context.Context, user *User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

func (r *repository) CreateSession(ctx context.Context, session *Session) error {
	return r.db.WithContext(ctx).Create(session).Error
}

func (r *repository) GetSessionByToken(ctx context.Context, token string) (*Session, error) {
	var session Session
	err := r.db.WithContext(ctx).Where("refresh_token = ?", token).First(&session).Error
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *repository) DeleteSession(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Where("refresh_token = ?", token).Delete(&Session{}).Error
}

func (r *repository) CreateMagicLink(ctx context.Context, token *MagicLinkToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *repository) GetMagicLink(ctx context.Context, token string) (*MagicLinkToken, error) {
	var result MagicLinkToken
	err := r.db.WithContext(ctx).Where("token = ?", token).First(&result).Error
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (r *repository) DeleteMagicLink(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Where("token = ?", token).Where("1=1").Delete(&MagicLinkToken{}).Error
}
