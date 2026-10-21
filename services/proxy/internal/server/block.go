package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

const (
	stageWAF       = "waf"
	stageCrowdSec  = "crowdsec"
	stageRateLimit = "ratelimit"
	stageGeo       = "geo"
	stageACL       = "acl"
)

// blockMeta is per-request detail filled in along the pipeline and reported
// in telemetry: which stage stopped the request and why, and which upstream
// answered when none did.
type blockMeta struct {
	Stage          string
	Detail         string
	CrowdSecOrigin string
	Upstream       string
	RequestID      string
}

type blockMetaKey struct{}

func attachBlockMeta(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), blockMetaKey{}, &blockMeta{RequestID: newRequestID()}))
}

func blockMetaFrom(r *http.Request) *blockMeta {
	if r == nil {
		return nil
	}
	v, _ := r.Context().Value(blockMetaKey{}).(*blockMeta)
	return v
}

func setBlockStage(r *http.Request, stage string) {
	if m := blockMetaFrom(r); m != nil {
		m.Stage = stage
	}
}

// setBlock records the stage and, in words, why it stopped the request.
func setBlock(r *http.Request, stage, detail string) {
	if m := blockMetaFrom(r); m != nil {
		m.Stage = stage
		m.Detail = detail
	}
}

func setCrowdsecOrigin(r *http.Request, origin string) {
	if m := blockMetaFrom(r); m != nil {
		m.CrowdSecOrigin = origin
	}
}

func setUpstream(r *http.Request, target string) {
	if m := blockMetaFrom(r); m != nil {
		m.Upstream = target
	}
}

func newRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
