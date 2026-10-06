package infrastructure

import (
	"strings"
	"testing"
	"time"

	"github.com/alora/auth/internal/config"
)

func TestDisabledIsNoop(t *testing.T) {
	m := NewMailer(config.MailConfig{}) // Host empty → disabled
	if m.Enabled() {
		t.Fatal("expected mailer disabled when Host is empty")
	}
	if err := m.SendInvitation("a@b.co", "http://x/invite", "Acme", time.Now()); err != nil {
		t.Errorf("disabled SendInvitation should be a no-op, got %v", err)
	}
	if err := m.SendPasswordReset("a@b.co", "http://x/reset", time.Now()); err != nil {
		t.Errorf("disabled SendPasswordReset should be a no-op, got %v", err)
	}
}

// Regression (audit critical #4): tenant-controlled text (e.g. clientName in the
// invite subject) must never inject headers. Without sanitisation a tenant admin
// could add Bcc/Reply-To to mail signed by our DKIM key.
func TestBuildMIMERejectsHeaderInjection(t *testing.T) {
	evil := "Acme\r\nBcc: attacker@evil.co\r\nX-Injected: yes"
	msg := string(buildMIME("no-reply@acme.co", "victim@x.co", "Invite to "+evil, "body", "<p>body</p>"))
	headerEnd := strings.Index(msg, "\r\n\r\n")
	if headerEnd < 0 {
		t.Fatal("no header/body separator")
	}
	headers := msg[:headerEnd]
	// The property that matters is that no NEW header LINE was created. The
	// payload text may legitimately survive inside the Subject *value* (harmless);
	// what must never happen is a line beginning with an injected field name.
	allowed := map[string]bool{"From": true, "To": true, "Subject": true, "MIME-Version": true, "Content-Type": true}
	for _, line := range strings.Split(headers, "\r\n") {
		name, _, found := strings.Cut(line, ":")
		if !found {
			t.Errorf("SECURITY: continuation/garbage line in header block: %q", line)
			continue
		}
		if !allowed[name] {
			t.Errorf("SECURITY: injected header line %q (field %q)", line, name)
		}
	}
	// The Subject must remain a single header line.
	if n := strings.Count(headers, "Subject:"); n != 1 {
		t.Errorf("expected exactly 1 Subject header, got %d", n)
	}
}

func TestBuildMIMEStructure(t *testing.T) {
	msg := string(buildMIME("Acme <no-reply@acme.co>", "user@x.co", "Hello", "plain-body-here", "<p>html-body-here</p>"))
	for _, want := range []string{
		"From: Acme <no-reply@acme.co>",
		"To: user@x.co",
		"Subject: Hello",
		"MIME-Version: 1.0",
		"multipart/alternative",
		"text/plain; charset=\"utf-8\"",
		"text/html; charset=\"utf-8\"",
		"plain-body-here",
		"<p>html-body-here</p>",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("MIME message missing %q", want)
		}
	}
}

// The envelope sender (MAIL FROM) is not the SMTP username. Providers use a
// token there — SendGrid's is the literal "apikey" — and a reverse-path that is
// not a mailbox either bounces or fails SPF/DMARC alignment, which delivers to
// spam while every log line says success.
func TestEnvelopeAddressPrefersTheFromHeader(t *testing.T) {
	cases := []struct {
		name, fromHeader, user, want string
	}{
		{"display name is stripped", `"Acme Corp" <no-reply@acme.com>`, "apikey", "no-reply@acme.com"},
		{"bare address passes through", "no-reply@acme.com", "apikey", "no-reply@acme.com"},
		{"username is only a fallback", "", "smtp-login@acme.com", "smtp-login@acme.com"},
		{"unparseable header falls back", "not an address", "smtp-login@acme.com", "smtp-login@acme.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := envelopeAddress(tc.fromHeader, tc.user); got != tc.want {
				t.Fatalf("envelopeAddress(%q, %q) = %q, want %q", tc.fromHeader, tc.user, got, tc.want)
			}
		})
	}
}

// An organisation name is chosen by a tenant admin and rendered in mail sent to
// people who are not yet users. Unescaped, it is markup in a stranger's inbox
// carrying our From address and DKIM signature.
func TestInvitationEscapesTheTenantName(t *testing.T) {
	m := NewMailer(config.MailConfig{Host: "smtp.test", Port: 587, User: "u", From: "no-reply@alora.test"})

	hostile := `Acme</strong></p><p><a href="https://evil.test">Verify now</a><p>`
	body := m.invitationHTML(hostile, "https://auth.test/invite?token=abc", "1 January 2027")

	if strings.Contains(body, `href="https://evil.test"`) {
		t.Fatalf("tenant name injected a live link into the invitation body:\n%s", body)
	}
	if !strings.Contains(body, "&lt;/strong&gt;") {
		t.Fatalf("tenant name was not escaped:\n%s", body)
	}
}
