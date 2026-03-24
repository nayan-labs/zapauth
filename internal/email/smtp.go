package email

import (
	"fmt"
	"net/smtp"

	"github.com/nayan-labs/zapauth/internal/config"
)

type Service interface {
	SendMagicLink(to, token string) error
}

type smtpService struct {
	cfg *config.Config
}

func NewSMTPService(cfg *config.Config) Service {
	return &smtpService{cfg: cfg}
}

func (s *smtpService) SendMagicLink(to, token string) error {
	if s.cfg.SMTPHost == "" {
		return fmt.Errorf("SMTP not configured")
	}

	auth := smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPass, s.cfg.SMTPHost)
	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)

	// Magic link verify endpoint will be /auth/verify?token=<token>
	link := fmt.Sprintf("http://localhost:%s/auth/verify?token=%s", s.cfg.Port, token)

	msg := []byte(fmt.Sprintf("To: %s\r\n"+
		"Subject: ZapAuth Magic Link Login\r\n"+
		"MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"+
		"<html><body><p>Click the link below to log in:</p>"+
		"<p><a href=\"%s\">%s</a></p></body></html>\r\n", to, link, link))

	// If missing credentials, some servers (like mailhog) might accept unauthenticated email.
	var a smtp.Auth
	if s.cfg.SMTPUser != "" || s.cfg.SMTPPass != "" {
		a = auth
	}

	return smtp.SendMail(addr, a, s.cfg.SMTPFrom, []string{to}, msg)
}
