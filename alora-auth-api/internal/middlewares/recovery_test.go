package middlewares

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// recoveringEngine mounts Recovery in its production position: after the
// request id and logger, before the error handler.
func recoveringEngine(logs *bytes.Buffer) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestID(), WithLogger(slog.New(slog.NewTextHandler(logs, nil))), Recovery(), ErrorHandler())
	r.GET("/panic", func(c *gin.Context) { panic("handler exploded") })
	r.GET("/panic-after-write", func(c *gin.Context) {
		c.String(http.StatusOK, "partial")
		panic("exploded mid-response")
	})
	return r
}

func TestRecoveryRendersTheErrorEnvelope(t *testing.T) {
	var logs bytes.Buffer
	w := httptest.NewRecorder()
	recoveringEngine(&logs).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/panic", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q is not JSON: %v", w.Body.String(), err)
	}
	reqID := w.Header().Get("X-Request-Id")
	if reqID == "" || len(body) != 2 || body["error"] != "Internal Server Error" || body["reqId"] != reqID {
		t.Errorf("body %v, want the 500 envelope carrying reqId %q", body, reqID)
	}
	if strings.Contains(w.Body.String(), "exploded") {
		t.Errorf("the panic value leaked into the response: %s", w.Body.String())
	}

	// Logged through the request logger: correlated, with the value and the stack.
	out := logs.String()
	for _, want := range []string{"panic recovered", "handler exploded", "reqId=" + reqID, "recovery_test.go"} {
		if !strings.Contains(out, want) {
			t.Errorf("log is missing %q:\n%s", want, out)
		}
	}
}

func TestRecoveryLeavesAStartedResponseAlone(t *testing.T) {
	var logs bytes.Buffer
	w := httptest.NewRecorder()
	recoveringEngine(&logs).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/panic-after-write", nil))

	if w.Code != http.StatusOK || w.Body.String() != "partial" {
		t.Errorf("got %d %q, want the partial 200 untouched", w.Code, w.Body.String())
	}
	if !strings.Contains(logs.String(), "exploded mid-response") {
		t.Errorf("the panic was not logged:\n%s", logs.String())
	}
}
