// Package mailer sends transactional email over SMTP. When Host is unset the
// mailer is a no-op (Enabled() == false) and callers return the invite/reset URL
// in the API response instead — matching the Node behavior.
package mailer

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/alora/auth/internal/config"
)

type Mailer struct {
	cfg config.MailConfig
}

func New(cfg config.MailConfig) *Mailer { return &Mailer{cfg: cfg} }

// Enabled reports whether SMTP is configured.
func (m *Mailer) Enabled() bool { return m.cfg.Host != "" }

func (m *Mailer) SendInvitation(to, inviteURL, clientName string, expiresAt time.Time) error {
	if !m.Enabled() {
		return nil
	}
	expiry := expiresAt.Format("2 January 2006")
	from := m.cfg.From
	if from == "" {
		from = fmt.Sprintf("%q <%s>", clientName, m.cfg.User)
	}
	text := "Hi,\n\nYou've been invited to join " + clientName + ".\n\nSet up your account here:\n" + inviteURL +
		"\n\nThis link expires on " + expiry + ".\n\nIf you didn't expect this invitation you can safely ignore it."
	html := "<p>Hi,</p><p>You've been invited to join <strong>" + clientName + "</strong>.</p>" +
		"<p><a href=\"" + inviteURL + "\" style=\"font-size:16px;font-weight:bold\">Set up your account</a></p>" +
		"<p style=\"color:#888;font-size:13px\">This link expires on " + expiry + ".<br>" +
		"If you didn't expect this invitation you can safely ignore it.</p>"
	return m.send(from, to, "You've been invited to "+clientName, text, html)
}

func (m *Mailer) SendPasswordReset(to, resetURL string, expiresAt time.Time) error {
	if !m.Enabled() {
		return nil
	}
	expiry := expiresAt.Format("2 January 2006, 15:04")
	from := m.cfg.From
	if from == "" {
		from = m.cfg.User
	}
	text := "Hi,\n\nA password reset was requested for your account.\n\nReset your password here:\n" + resetURL +
		"\n\nThis link expires on " + expiry + ".\n\nIf you didn't request this you can safely ignore this email."
	html := "<p>Hi,</p><p>A password reset was requested for your account.</p>" +
		"<p><a href=\"" + resetURL + "\" style=\"font-size:16px;font-weight:bold\">Reset your password</a></p>" +
		"<p style=\"color:#888;font-size:13px\">This link expires on " + expiry + ".<br>" +
		"If you didn't request this you can safely ignore this email.</p>"
	return m.send(from, to, "Reset your Alora Auth password", text, html)
}

func (m *Mailer) send(fromHeader, to, subject, text, html string) error {
	msg := buildMIME(fromHeader, to, subject, text, html)
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	auth := smtp.PlainAuth("", m.cfg.User, m.cfg.Pass, m.cfg.Host)
	envelopeFrom := m.cfg.User // MAIL FROM must be a bare address

	if m.cfg.Secure { // implicit TLS (port 465)
		return sendImplicitTLS(addr, m.cfg.Host, auth, envelopeFrom, to, msg)
	}
	// STARTTLS (port 587) — smtp.SendMail upgrades the connection and authenticates.
	return smtp.SendMail(addr, auth, envelopeFrom, []string{to}, msg)
}

// sanitizeHeader strips CR, LF and NUL from a header value. Without this, any
// tenant-controlled string reaching a header (notably clientName in the invite
// Subject) could inject arbitrary headers — Bcc exfiltration or a forged
// Reply-To — into mail signed by our DKIM key. net/smtp validates only the
// envelope, never the message body we build here.
func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ", "\x00", "").Replace(s)
}

func buildMIME(fromHeader, to, subject, text, html string) []byte {
	const boundary = "alora-alt-boundary-8f2a1c"
	fromHeader, to, subject = sanitizeHeader(fromHeader), sanitizeHeader(to), sanitizeHeader(subject)
	var b strings.Builder
	b.WriteString("From: " + fromHeader + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n")
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n")
	b.WriteString(text + "\r\n\r\n")
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n\r\n")
	b.WriteString(html + "\r\n\r\n")
	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String())
}

func sendImplicitTLS(addr, host string, auth smtp.Auth, from, to string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Auth(auth); err != nil {
		return err
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
