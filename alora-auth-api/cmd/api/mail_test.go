package main

// The mail-enabled branches. Every other test runs with MAIL_HOST unset, which
// takes the "share the link by hand" path, so these swap in a fake mailer to
// cover what a deployment with working SMTP does.

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

type sentMail struct {
	kind       string
	to         string
	url        string
	clientName string
	expiresAt  time.Time
}

// fakeMailer records what would have been sent. With panics set, it panics after
// recording, to prove the detached send is recovered.
type fakeMailer struct {
	panics bool
	sent   chan sentMail
}

func newFakeMailer(panics bool) *fakeMailer {
	return &fakeMailer{panics: panics, sent: make(chan sentMail, 4)}
}

func (m *fakeMailer) Enabled() bool { return true }

func (m *fakeMailer) SendInvitation(to, inviteURL, clientName string, expiresAt time.Time) error {
	m.sent <- sentMail{kind: "invitation", to: to, url: inviteURL, clientName: clientName, expiresAt: expiresAt}
	if m.panics {
		panic("mailer exploded")
	}
	return nil
}

func (m *fakeMailer) SendPasswordReset(to, resetURL string, expiresAt time.Time) error {
	m.sent <- sentMail{kind: "reset", to: to, url: resetURL, expiresAt: expiresAt}
	if m.panics {
		panic("mailer exploded")
	}
	return nil
}

func (m *fakeMailer) next(t *testing.T) sentMail {
	t.Helper()
	select {
	case s := <-m.sent:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("no email was sent")
		return sentMail{}
	}
}

// withMailer swaps the app's router for one wired with mail.
func (a *app) withMailer(mail mailer) {
	a.t.Helper()
	m, err := newModulesWith(a.cfg, testLogger(), a.db, mail)
	if err != nil {
		a.t.Fatal(err)
	}
	r, err := newRouter(a.cfg, testLogger(), m)
	if err != nil {
		a.t.Fatal(err)
	}
	a.m, a.r = m, r
}

func TestInvitationIsEmailed(t *testing.T) {
	a := newApp(t)
	mail := newFakeMailer(false)
	a.withMailer(mail)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	email := "mailed-" + randSuffix(t) + "@acme.test"
	w := a.post("/api/admin/invitations", map[string]any{"email": email}, bearer(s.Access))
	expect(t, w, http.StatusCreated, "invite")
	sent := mail.next(t)
	if sent.kind != "invitation" || sent.to != email || sent.clientName != co.Name ||
		!strings.HasPrefix(sent.url, testFrontend+"/accept-invitation?token=") || sent.url != jsonField(w, "invite_url") {
		t.Errorf("sent %+v", sent)
	}
}

// With mail working, a reset link is emailed and NEVER returned.
func TestResetIsEmailedNotReturned(t *testing.T) {
	a := newApp(t)
	mail := newFakeMailer(false)
	a.withMailer(mail)
	co := a.newCompany()
	m := a.newMember(co, "")
	s := a.login(a.newAdmin(co))
	w := a.post("/api/admin/users/"+m.ID+"/password-reset", nil, bearer(s.Access))
	expect(t, w, http.StatusOK, "issue")
	if strings.Contains(w.Body.String(), "reset_url") {
		t.Fatalf("SECURITY: the reset link was returned: %s", w.Body.String())
	}
	sent := mail.next(t)
	if sent.kind != "reset" || sent.to != m.Email || !strings.HasPrefix(sent.url, testFrontend+"/reset-password?token=") {
		t.Errorf("sent %+v", sent)
	}
	expect(t, a.post("/auth/reset-password", map[string]any{"token": tokenOf(t, sent.url), "new_password": "a mailed new password"}),
		http.StatusNoContent, "redeem the mailed link")
}

// A mailer that blows up must not take the request, or the process, with it.
func TestPanickingMailerIsContained(t *testing.T) {
	a := newApp(t)
	mail := newFakeMailer(true)
	a.withMailer(mail)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	w := a.post("/api/admin/invitations", map[string]any{"email": "boom-" + randSuffix(t) + "@acme.test"}, bearer(s.Access))
	expect(t, w, http.StatusCreated, "invite with a panicking mailer")
	mail.next(t)
	time.Sleep(50 * time.Millisecond) // let the recovered goroutine finish
	expect(t, a.get("/health"), http.StatusOK, "still serving")
}
