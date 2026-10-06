package shared

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// ClientMeta is the request fingerprint stored with a session for the admin UI.
// It is display-only and never used for a security decision.
type ClientMeta struct {
	IP          string
	UserAgent   string
	DeviceLabel string
}

// maxUserAgent bounds what an untrusted header can store.
const maxUserAgent = 512

// MetaFrom captures the request fingerprint. ClientIP() is only trustworthy
// because SetTrustedProxies is an explicit allowlist; with Gin's default
// trust-all a client could spoof this via X-Forwarded-For.
func MetaFrom(c *gin.Context) ClientMeta {
	ua := StorableText(c.Request.UserAgent(), maxUserAgent)
	return ClientMeta{IP: c.ClientIP(), UserAgent: ua, DeviceLabel: deviceLabel(ua)}
}

// StorableText is s made storable, for display-only text the caller does not
// control and must not be refused over — a browser's identity: bytes that are
// not UTF-8 become U+FFFD, NULs are dropped, and it is cut to at most max bytes
// without splitting a character.
func StorableText(s string, max int) string {
	s = strings.ReplaceAll(strings.ToValidUTF8(s, "�"), "\x00", "")
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "")
	}
	return s
}

// deviceLabel renders a coarse, human-readable label for the sessions UI. It is
// display-only and never used for any security decision.
func deviceLabel(ua string) string {
	switch {
	case ua == "":
		return "Unknown device"
	case strings.Contains(ua, "Edg/"):
		return "Edge"
	case strings.Contains(ua, "Chrome/"):
		return "Chrome"
	case strings.Contains(ua, "Firefox/"):
		return "Firefox"
	case strings.Contains(ua, "Safari/"):
		return "Safari"
	default:
		return "Unknown device"
	}
}
