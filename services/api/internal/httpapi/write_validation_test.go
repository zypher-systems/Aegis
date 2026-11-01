package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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
