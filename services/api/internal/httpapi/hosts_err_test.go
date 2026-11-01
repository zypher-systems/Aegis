package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zypher-systems/aegis/services/api/internal/store"
)

func TestWriteHostErrConflict(t *testing.T) {
	rr := httptest.NewRecorder()
	if !writeHostErr(rr, &store.DomainConflictError{Domain: "demo.local"}, "create failed") {
		t.Fatal("expected write")
	}
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d", rr.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "demo.local is already in use" {
		t.Fatalf("error = %q", body["error"])
	}

	rr = httptest.NewRecorder()
	writeHostErr(rr, store.ErrDomainTaken, "create failed")
	if rr.Code != http.StatusConflict {
		t.Fatalf("taken status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	writeHostErr(rr, errors.New("boom"), "create failed")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("fallback status = %d", rr.Code)
	}
}

// Two imports can race to the same domain; the loser should say so.
func TestHostErrTextNamesATakenDomain(t *testing.T) {
	if got := hostErrText(store.ErrDomainTaken, "create failed"); got == "create failed" {
		t.Fatalf("got %q", got)
	}
	if got := hostErrText(errors.New("boom"), "create failed"); got != "create failed" {
		t.Fatalf("got %q", got)
	}
}
