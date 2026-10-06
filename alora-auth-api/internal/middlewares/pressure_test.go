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

type fakePressure struct{ over bool }

func (f *fakePressure) Overloaded() bool { return f.over }

func TestUnderPressureShedsUntilMemoryRecovers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var logs bytes.Buffer
	p := &fakePressure{}
	r := gin.New()
	r.Use(RequestID(), WithLogger(slog.New(slog.NewTextHandler(&logs, nil))), UnderPressure(p))
	r.GET("/work", func(c *gin.Context) { c.String(http.StatusOK, "done") })
	get := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/work", nil))
		return w
	}

	if w := get(); w.Code != http.StatusOK || w.Body.String() != "done" {
		t.Fatalf("under the ceiling: %d %q, want the handler's 200", w.Code, w.Body.String())
	}

	p.over = true
	for range 3 {
		w := get()
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "10" {
			t.Fatalf("over the ceiling: %d, Retry-After %q; want 503 and 10", w.Code, w.Header().Get("Retry-After"))
		}
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("body %q is not JSON: %v", w.Body.String(), err)
		}
		reqID := w.Header().Get("X-Request-Id")
		if len(body) != 2 || body["error"] != "Internal Server Error" || body["reqId"] != reqID {
			t.Errorf("body %v, want the ≥500 envelope carrying reqId %q", body, reqID)
		}
	}

	p.over = false
	if w := get(); w.Code != http.StatusOK {
		t.Fatalf("after recovery: %d, want 200", w.Code)
	}

	// One line when shedding starts and one when it stops, never one per request.
	out := logs.String()
	if n := strings.Count(out, "shedding every request"); n != 1 {
		t.Errorf("logged the start of shedding %d times, want once:\n%s", n, out)
	}
	if n := strings.Count(out, "serving requests again"); n != 1 {
		t.Errorf("logged the recovery %d times, want once:\n%s", n, out)
	}
}
