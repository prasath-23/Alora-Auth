// Package mailer sends transactional email over SMTP. When Host is unset the
// mailer is a no-op (Enabled() == false) and callers return the invite/reset URL
// in the API response instead — matching the Node behavior.
package mailer

import (
	"crypto/tls"
	"fmt"
	"html"
	"net"
	"net/mail"
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
	return m.send(from, to, "You've been invited to "+clientName, text,
		m.invitationHTML(clientName, inviteURL, expiry))
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
	return m.send(from, to, "Reset your Alora Auth password", text, m.resetHTML(resetURL, expiry))
}

// invitationHTML is separate from SendInvitation so the escaping below can be
// tested without an SMTP server -- SendInvitation returns early when mail is not
// configured, which is exactly the state a test runs in.
//
// clientName is tenant-controlled: an admin picks their organisation's name.
// Interpolated raw it becomes markup in someone else's inbox -- close the
// paragraph, open a link, and the invitation carries an attacker's URL under our
// From address and DKIM signature. Escaped, the worst case is an organisation
// with an ugly name.
func (m *Mailer) invitationHTML(clientName, inviteURL, expiry string) string {
	return "<p>Hi,</p><p>You've been invited to join <strong>" + html.EscapeString(clientName) + "</strong>.</p>" +
		"<p><a href=\"" + html.EscapeString(inviteURL) + "\" style=\"font-size:16px;font-weight:bold\">Set up your account</a></p>" +
		"<p style=\"color:#888;font-size:13px\">This link expires on " + html.EscapeString(expiry) + ".<br>" +
		"If you didn't expect this invitation you can safely ignore it.</p>"
}

func (m *Mailer) resetHTML(resetURL, expiry string) string {
	return "<p>Hi,</p><p>A password reset was requested for your account.</p>" +
		"<p><a href=\"" + html.EscapeString(resetURL) + "\" style=\"font-size:16px;font-weight:bold\">Reset your password</a></p>" +
		"<p style=\"color:#888;font-size:13px\">This link expires on " + html.EscapeString(expiry) + ".<br>" +
		"If you didn't request this you can safely ignore this email.</p>"
}

func (m *Mailer) send(fromHeader, to, subject, text, htmlBody string) error {
	msg := buildMIME(fromHeader, to, subject, text, htmlBody)
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	auth := smtp.PlainAuth("", m.cfg.User, m.cfg.Pass, m.cfg.Host)
	envelopeFrom := envelopeAddress(fromHeader, m.cfg.User)

	if m.cfg.Secure { // implicit TLS (port 465)
		return sendImplicitTLS(addr, m.cfg.Host, auth, envelopeFrom, to, msg)
	}
	// STARTTLS (port 587) — smtp.SendMail upgrades the connection and authenticates.
	return smtp.SendMail(addr, auth, envelopeFrom, []string{to}, msg)
}

// envelopeAddress picks the bare address for MAIL FROM.
//
// The SMTP username is the wrong source and was the previous one. On SendGrid it
// is the literal string "apikey"; on Postmark and Mailgun it is a server token
// or a domain-scoped login. None is a mailbox, so the reverse-path is either
// rejected outright or fails SPF and DMARC alignment -- mail that authenticates
// fine and lands in spam, which is the harder failure to diagnose. An empty
// username is worse: `MAIL FROM:<>` is the null sender reserved for bounces, and
// relays reject ordinary mail that claims it.
//
// The From header is the right source: it is the address the recipient sees and
// the one the domain's SPF record is written for. The username is kept only as a
// fallback for a relay whose login genuinely is the mailbox.
func envelopeAddress(fromHeader, user string) string {
	if addr, err := mail.ParseAddress(fromHeader); err == nil {
		return addr.Address
	}
	return user
}

// sanitizeHeader strips CR, LF and NUL from a header value. Without this, any
// tenant-controlled string reaching a header (notably clientName in the invite
// Subject) could inject arbitrary headers — Bcc exfiltration or a forged
// Reply-To — into mail signed by our DKIM key. net/smtp validates only the
// envelope, never the message body we build here.
func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ", "\x00", "").Replace(s)
}

func buildMIME(fromHeader, to, subject, text, htmlBody string) []byte {
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
	b.WriteString(htmlBody + "\r\n\r\n")
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
