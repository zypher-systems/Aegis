package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNoticesUnauthorized(t *testing.T) {
	s := New(Deps{})
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/notices", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
