package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/zypher-systems/aegis/services/api/internal/store"
)

// withID routes a request the way chi would for /{id}.
func withID(r *http.Request, id string) *http.Request {
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}

// These run with no store: a request that reached one would panic, so each
// passes only if the write is refused before anything is saved.
func TestHostWritesRefuseMalformedReferences(t *testing.T) {
	s := &Server{}
	for _, field := range []string{"access_list_id", "waf_profile_id", "cert_id"} {
		body := fmt.Sprintf(`{"domain_names":["app.example.com"],"upstream_host":"10.0.0.5","upstream_port":8080,"tls_mode":"none",%q:"not-a-uuid"}`, field)

		rr := httptest.NewRecorder()
		s.createHost(rr, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), field) {
			t.Errorf("create with bad %s: %d %s", field, rr.Code, rr.Body)
		}

		rr = httptest.NewRecorder()
		r := withID(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), uuid.NewString())
		s.updateHost(rr, r)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), field) {
			t.Errorf("update with bad %s: %d %s", field, rr.Code, rr.Body)
		}
	}
}

func TestUpdateUserRefusesShortPasswordBeforeSaving(t *testing.T) {
	s := &Server{}
	rr := httptest.NewRecorder()
	body := `{"email":"new@example.com","name":"New","password":"short"}`
	s.updateUser(rr, withID(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), uuid.NewString()))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d: %s", rr.Code, rr.Body)
	}
}

func TestHostRefProblemAllowsClearing(t *testing.T) {
	empty, valid, bad := "", uuid.NewString(), "x"
	for _, hr := range []hostRequest{
		{},
		{AccessListID: &empty, WAFProfileID: &empty, CertID: &empty},
		{AccessListID: &valid, WAFProfileID: &valid, CertID: &valid},
	} {
		if msg := hr.refProblem(); msg != "" {
			t.Errorf("%+v refused: %s", hr, msg)
		}
	}
	if msg := (hostRequest{WAFProfileID: &bad}).refProblem(); msg == "" {
		t.Error("malformed waf_profile_id accepted")
	}
}

// A host copied from the API has ids and no names: importing it as it stands
// would silently drop the access list and WAF profile.
func TestImportRefusesProtectionGivenOnlyByID(t *testing.T) {
	id, name, empty := uuid.NewString(), "Office", ""
	if msg := importRefProblem(hostRequest{AccessListID: &id}, nil, nil); msg == "" {
		t.Error("access list id without a name accepted")
	}
	if msg := importRefProblem(hostRequest{WAFProfileID: &id}, nil, &empty); msg == "" {
		t.Error("WAF profile id without a name accepted")
	}
	if msg := importRefProblem(hostRequest{AccessListID: &id, WAFProfileID: &id}, &name, &name); msg != "" {
		t.Errorf("named references refused: %s", msg)
	}
	if msg := importRefProblem(hostRequest{AccessListID: &empty}, nil, nil); msg != "" {
		t.Errorf("host with no protection refused: %s", msg)
	}
}

func TestResolveCertReportsWhatBindCertWrites(t *testing.T) {
	s := &Server{} // no certificate service
	h := proxyHost("10.0.0.5")
	h.TLSMode = "auto"
	if status, msg := s.resolveCert(context.Background(), h); status != http.StatusBadGateway || msg == "" {
		t.Fatalf("auto without a certificate service: %d %q", status, msg)
	}
	h.TLSMode = "custom"
	if status, _ := s.resolveCert(context.Background(), h); status != http.StatusBadRequest {
		t.Fatalf("custom without cert_id: %d", status)
	}
	h.TLSMode = "none"
	id := uuid.New()
	h.CertID = &id
	if status, _ := s.resolveCert(context.Background(), h); status != 0 || h.CertID != nil {
		t.Fatalf("tls none keeps its certificate: %d %v", status, h.CertID)
	}
}

func TestWaitForCertAppliesTheResult(t *testing.T) {
	id := uuid.New()
	h := &store.Host{}
	status, _ := waitForCert(context.Background(), h, time.Now().Add(time.Minute), func(own *store.Host) (int, string) {
		own.CertID = &id
		return 0, ""
	})
	if status != 0 || h.CertID == nil || *h.CertID != id {
		t.Fatalf("status %d, cert %v", status, h.CertID)
	}
}

// The response has to go out in time even though the order cannot be stopped.
func TestWaitForCertAnswersAtTheDeadline(t *testing.T) {
	release, ended := make(chan struct{}), make(chan struct{})
	id := uuid.New()
	h := &store.Host{}
	status, msg := waitForCert(context.Background(), h, time.Now().Add(20*time.Millisecond), func(own *store.Host) (int, string) {
		<-release
		own.CertID = &id
		close(ended)
		return 0, ""
	})
	if status != http.StatusGatewayTimeout || !strings.Contains(msg, "in a few minutes") {
		t.Fatalf("status %d, %q", status, msg)
	}
	if h.CertID != nil {
		t.Fatal("a host left out of the import was given a certificate")
	}
	close(release) // the order carries on and finishes
	<-ended
}

// A client that left needs no answer, and giving up would strand the
// certificate: the wait runs on past the deadline so the host can be saved.
func TestWaitForCertSeesTheOrderThroughForAGoneClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	id := uuid.New()
	h := &store.Host{}
	status, _ := waitForCert(ctx, h, time.Now().Add(10*time.Millisecond), func(own *store.Host) (int, string) {
		time.Sleep(60 * time.Millisecond)
		own.CertID = &id
		return 0, ""
	})
	if status != 0 || h.CertID == nil {
		t.Fatalf("status %d, cert %v: the order was abandoned", status, h.CertID)
	}
}

// Past the import's limits a host that needs no order is still saved, and one
// that would place an order is not started.
func TestImportCertLimitsOnlyHostsThatOrder(t *testing.T) {
	late := time.Now().Add(-10 * time.Minute)
	issued := 0
	issue := func(*store.Host) (int, string) {
		issued++
		return 0, ""
	}
	for _, mode := range []string{"none", "custom", ""} {
		if status, msg := importCert(context.Background(), &store.Host{TLSMode: mode}, late, issue); status != 0 {
			t.Errorf("tls_mode %q left out: %d %q", mode, status, msg)
		}
	}
	if issued != 3 {
		t.Fatalf("issued %d times, want 3", issued)
	}
	status, msg := importCert(context.Background(), &store.Host{TLSMode: "auto"}, late, issue)
	if status == 0 || !strings.Contains(msg, "not reached") {
		t.Fatalf("auto host past the budget: %d %q", status, msg)
	}
	if issued != 3 {
		t.Fatal("an order was started past the budget")
	}
}
