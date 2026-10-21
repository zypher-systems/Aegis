// Package telemetry receives batched access events from data-plane nodes,
// keeps a live Redis/memory view, and flushes hourly/daily Postgres rollups.
package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/oschwald/maxminddb-golang"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/services/api/internal/store"
)

const (
	liveCap     = 500
	liveRedis   = "aegis:analytics:live"
	flushEvery  = time.Minute
	pruneEvery  = 6 * time.Hour
	onlineAfter = 60 * time.Second

	// The request log is written in batches this often; at most
	// logPendingCap events wait between writes (more are counted and dropped
	// rather than growing memory while Postgres is slow or down).
	logFlushEvery = 2 * time.Second
	logPendingCap = 50_000
)

// Request log modes (AEGIS_REQUEST_LOG).
const (
	LogAll      = "all"
	LogSecurity = "security" // only requests a stage blocked or the WAF flagged
	LogOff      = "off"
)

// Event is the JSON shape stored in the live ring and the request log, and
// returned to the dashboard.
type Event struct {
	ID             string  `json:"id"`
	TimestampMs    int64   `json:"timestamp_unix_ms"`
	HostID         string  `json:"host_id"`
	NodeID         string  `json:"node_id"`
	Domain         string  `json:"domain"`
	Method         string  `json:"method"`
	Path           string  `json:"path"`
	Status         int32   `json:"status"`
	DurationMs     float64 `json:"duration_ms"`
	ClientIP       string  `json:"client_ip"`
	UserAgent      string  `json:"user_agent"`
	BytesSent      int64   `json:"bytes_sent"`
	Country        string  `json:"country,omitempty"`
	WAFAction      string  `json:"waf_action,omitempty"`
	WAFRuleID      string  `json:"waf_rule_id,omitempty"`
	WAFScore       float64 `json:"waf_score,omitempty"`
	BlockStage     string  `json:"block_stage,omitempty"`
	CrowdSecOrigin string  `json:"crowdsec_origin,omitempty"`

	Query         string     `json:"query,omitempty"`
	Referer       string     `json:"referer,omitempty"`
	Protocol      string     `json:"protocol,omitempty"`
	Scheme        string     `json:"scheme,omitempty"`
	TLSVersion    string     `json:"tls_version,omitempty"`
	Upstream      string     `json:"upstream,omitempty"`
	PeerIP        string     `json:"peer_ip,omitempty"`
	BytesReceived int64      `json:"bytes_received,omitempty"`
	BlockDetail   string     `json:"block_detail,omitempty"`
	WAFMatches    []WAFMatch `json:"waf_matches,omitempty"`
}

// WAFMatch is one CRS rule that matched a request.
type WAFMatch struct {
	RuleID   string `json:"rule_id"`
	Message  string `json:"message"`
	Severity int32  `json:"severity"`
	Variable string `json:"variable,omitempty"`
	Key      string `json:"key,omitempty"`
	Value    string `json:"value,omitempty"`
}

// Flagged reports whether a security stage blocked the request or the WAF
// matched it (Detect mode).
func (e Event) Flagged() bool { return e.BlockStage != "" || e.WAFAction != "" }

type Options struct {
	Store     *store.Store
	Redis     *redis.Client
	GeoIPMMDB string
	TouchNode func(ctx context.Context, id uuid.UUID)

	// RequestLog is LogAll (default), LogSecurity or LogOff.
	RequestLog string
	// LogRetention keeps served requests; SecurityRetention keeps blocked
	// and flagged ones. Defaults 7 and 30 days.
	LogRetention      time.Duration
	SecurityRetention time.Duration
}

type Service struct {
	aegisv1.UnimplementedTelemetryServiceServer
	received atomic.Int64
	st       *store.Store
	rdb      *redis.Client
	geo      func(net.IP) (string, bool)
	touch    func(ctx context.Context, id uuid.UUID)

	logMode      string
	logKeep      time.Duration
	securityKeep time.Duration
	logDropped   atomic.Int64

	mu         sync.Mutex
	live       []Event
	pending    map[rollupKey]*rollupAcc
	pendingGeo map[geoKey]int64
	pendingLog []Event
}

type geoKey struct {
	hour    time.Time
	day     time.Time
	host    string
	country string
}

type rollupKey struct {
	hour        time.Time
	day         time.Time
	host        string
	domain      string
	statusClass int
	blockStage  string
}

type rollupAcc struct {
	count  int64
	latSum float64
	bytes  int64
}

func New(opts Options) *Service {
	s := &Service{
		st:           opts.Store,
		rdb:          opts.Redis,
		touch:        opts.TouchNode,
		pending:      map[rollupKey]*rollupAcc{},
		pendingGeo:   map[geoKey]int64{},
		logMode:      NormalizeLogMode(opts.RequestLog),
		logKeep:      opts.LogRetention,
		securityKeep: opts.SecurityRetention,
	}
	if s.logKeep <= 0 {
		s.logKeep = 7 * 24 * time.Hour
	}
	if s.securityKeep <= 0 {
		s.securityKeep = 30 * 24 * time.Hour
	}
	if s.securityKeep < s.logKeep {
		s.securityKeep = s.logKeep
	}
	if opts.GeoIPMMDB != "" {
		if lookup, err := openGeoIP(opts.GeoIPMMDB); err != nil {
			log.Printf("telemetry: geoip mmdb %s: %v (country skipped)", opts.GeoIPMMDB, err)
		} else {
			s.geo = lookup
		}
	}
	return s
}

// NormalizeLogMode maps AEGIS_REQUEST_LOG to a mode; unknown means all.
func NormalizeLogMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case LogSecurity:
		return LogSecurity
	case LogOff, "none", "false", "0":
		return LogOff
	default:
		return LogAll
	}
}

// LogMode is the request log mode in effect.
func (s *Service) LogMode() string { return s.logMode }

func openGeoIP(path string) (func(net.IP) (string, bool), error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return func(ip net.IP) (string, bool) {
		var rec struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if err := db.Lookup(ip, &rec); err != nil || rec.Country.ISOCode == "" {
			return "", false
		}
		return rec.Country.ISOCode, true
	}, nil
}

// Start flushes pending rollups and prunes retained tables until ctx is cancelled.
func (s *Service) Start(ctx context.Context) {
	s.prune(ctx)
	flush := time.NewTicker(flushEvery)
	prune := time.NewTicker(pruneEvery)
	logs := time.NewTicker(logFlushEvery)
	defer flush.Stop()
	defer prune.Stop()
	defer logs.Stop()
	for {
		select {
		case <-ctx.Done():
			s.Flush(context.Background())
			s.FlushLog(context.Background())
			return
		case <-flush.C:
			s.Flush(ctx)
		case <-logs.C:
			s.FlushLog(ctx)
		case <-prune.C:
			s.prune(ctx)
		}
	}
}

// Hydrate refills the live window from the request log, so the dashboard's
// live panels are not empty after an API restart. Events that arrived first
// stay newest.
func (s *Service) Hydrate(ctx context.Context) {
	if s.st == nil {
		return
	}
	raw, err := s.st.RecentRequestLog(ctx, liveCap)
	if err != nil {
		log.Printf("telemetry: reload live window: %v", err)
		return
	}
	s.seedLive(raw)
}

func (s *Service) seedLive(raw []json.RawMessage) {
	old := make([]Event, 0, len(raw))
	for i := len(raw) - 1; i >= 0; i-- { // newest first → oldest first
		var e Event
		if json.Unmarshal(raw[i], &e) == nil {
			old = append(old, e)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	live := append(old, s.live...)
	if len(live) > liveCap {
		live = live[len(live)-liveCap:]
	}
	s.live = live
}

// Received returns the total events ingested since startup.
func (s *Service) Received() int64 { return s.received.Load() }

func (s *Service) Push(stream grpc.ClientStreamingServer[aegisv1.TelemetryEvent, aegisv1.TelemetryAck]) error {
	var n int64
	ctx := stream.Context()
	nodeID := nodeIDFromPeer(ctx)
	for {
		if s.st != nil && s.st.NodeIDRevoked(nodeID) {
			return status.Error(codes.Unauthenticated, "node revoked")
		}
		ev, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&aegisv1.TelemetryAck{Received: n})
		}
		if err != nil {
			return err
		}
		s.Ingest(ctx, ev)
		n++
	}
}

// Ingest records one access event. Safe for tests without Redis/Postgres.
func (s *Service) Ingest(ctx context.Context, ev *aegisv1.TelemetryEvent) {
	if ev == nil {
		return
	}
	e := Event{
		ID:             ev.GetRequestId(),
		TimestampMs:    ev.GetTimestampUnixMs(),
		HostID:         ev.GetHostId(),
		NodeID:         ev.GetNodeId(),
		Domain:         ev.GetDomain(),
		Method:         ev.GetMethod(),
		Path:           ev.GetPath(),
		Status:         ev.GetStatus(),
		DurationMs:     ev.GetDurationMs(),
		ClientIP:       ev.GetClientIp(),
		UserAgent:      ev.GetUserAgent(),
		BytesSent:      ev.GetBytesSent(),
		Country:        ev.GetCountry(),
		WAFAction:      ev.GetWafAction(),
		WAFRuleID:      ev.GetWafRuleId(),
		WAFScore:       ev.GetWafScore(),
		BlockStage:     normalizeStage(ev.GetBlockStage()),
		CrowdSecOrigin: ev.GetCrowdsecOrigin(),
		Query:          ev.GetQuery(),
		Referer:        ev.GetReferer(),
		Protocol:       ev.GetProtocol(),
		Scheme:         ev.GetScheme(),
		TLSVersion:     ev.GetTlsVersion(),
		Upstream:       ev.GetUpstream(),
		PeerIP:         ev.GetPeerIp(),
		BytesReceived:  ev.GetBytesReceived(),
		BlockDetail:    ev.GetBlockDetail(),
	}
	for _, m := range ev.GetWafMatches() {
		e.WAFMatches = append(e.WAFMatches, WAFMatch{
			RuleID: m.GetRuleId(), Message: m.GetMessage(), Severity: m.GetSeverity(),
			Variable: m.GetVariable(), Key: m.GetKey(), Value: m.GetValue(),
		})
	}
	if e.ID == "" {
		// Nodes older than 1.7.1 send no id.
		e.ID = strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	if e.TimestampMs == 0 {
		e.TimestampMs = time.Now().UnixMilli()
	}
	if e.Country == "" && s.geo != nil && e.ClientIP != "" {
		if ip := net.ParseIP(e.ClientIP); ip != nil {
			if cc, ok := s.geo(ip); ok {
				e.Country = cc
			}
		}
	}

	s.received.Add(1)
	s.mu.Lock()
	s.live = append(s.live, e)
	if len(s.live) > liveCap {
		s.live = append([]Event(nil), s.live[len(s.live)-liveCap:]...)
	}
	ts := time.UnixMilli(e.TimestampMs).UTC()
	key := rollupKey{
		hour:        ts.Truncate(time.Hour),
		day:         time.Date(ts.Year(), ts.Month(), ts.Day(), 0, 0, 0, 0, time.UTC),
		host:        e.HostID,
		domain:      e.Domain,
		statusClass: statusClass(e.Status),
		blockStage:  e.BlockStage,
	}
	acc := s.pending[key]
	if acc == nil {
		acc = &rollupAcc{}
		s.pending[key] = acc
	}
	acc.count++
	acc.latSum += e.DurationMs
	acc.bytes += e.BytesSent
	cc := e.Country
	gk := geoKey{hour: key.hour, day: key.day, host: e.HostID, country: cc}
	s.pendingGeo[gk] += 1
	if s.logMode == LogAll || (s.logMode == LogSecurity && e.Flagged()) {
		if len(s.pendingLog) < logPendingCap {
			s.pendingLog = append(s.pendingLog, e)
		} else {
			s.logDropped.Add(1)
		}
	}
	s.mu.Unlock()

	if s.rdb != nil {
		if b, err := json.Marshal(e); err == nil {
			pipe := s.rdb.Pipeline()
			pipe.LPush(ctx, liveRedis, b)
			pipe.LTrim(ctx, liveRedis, 0, liveCap-1)
			pipe.Expire(ctx, liveRedis, 24*time.Hour)
			_, _ = pipe.Exec(ctx)
		}
	}
	if s.touch != nil && e.NodeID != "" {
		if id, err := uuid.Parse(e.NodeID); err == nil {
			s.touch(ctx, id)
		}
	}
}

// Live returns the newest events, newest first.
func (s *Service) Live(limit int) []Event {
	if limit <= 0 {
		limit = 50
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.live)
	if n == 0 {
		return nil
	}
	out := make([]Event, 0, min(limit, n))
	for i := n - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.live[i])
	}
	return out
}

type HistBucket struct {
	Le    float64 `json:"le"`
	Count int     `json:"count"`
}

type CountRow struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type Summary struct {
	Received       int64        `json:"received"`
	WindowEvents   int          `json:"window_events"`
	Blocked        int          `json:"blocked"`
	P50Ms          float64      `json:"p50_ms"`
	P99Ms          float64      `json:"p99_ms"`
	RPS            float64      `json:"rps"`
	Histogram      []HistBucket `json:"histogram"`
	TopPaths       []CountRow   `json:"top_paths"`
	TopClients     []CountRow   `json:"top_clients"`
	Geo            []CountRow   `json:"geo"`
	BlockedByStage []CountRow   `json:"blocked_by_stage"`
}

var histEdges = []float64{1, 5, 10, 25, 50, 100, 250}

// Summary aggregates the live window.
func (s *Service) Summary() Summary {
	s.mu.Lock()
	evs := append([]Event(nil), s.live...)
	s.mu.Unlock()

	out := Summary{
		Received: s.received.Load(), WindowEvents: len(evs),
		Histogram:      make([]HistBucket, len(histEdges)+1),
		TopPaths:       []CountRow{},
		TopClients:     []CountRow{},
		Geo:            []CountRow{},
		BlockedByStage: []CountRow{},
	}
	for i, le := range histEdges {
		out.Histogram[i].Le = le
	}
	out.Histogram[len(histEdges)].Le = 0 // overflow bucket, le=0 means +Inf

	if len(evs) == 0 {
		return out
	}
	lats := make([]float64, 0, len(evs))
	paths := map[string]int{}
	clients := map[string]int{}
	geo := map[string]int{}
	stages := map[string]int{}
	var oldest, newest int64
	for i, e := range evs {
		lats = append(lats, e.DurationMs)
		paths[e.Path]++
		if e.ClientIP != "" {
			clients[e.ClientIP]++
		}
		if e.Country != "" {
			geo[e.Country]++
		}
		if e.BlockStage != "" {
			out.Blocked++
			stages[e.BlockStage]++
		}
		if i == 0 || e.TimestampMs < oldest {
			oldest = e.TimestampMs
		}
		if e.TimestampMs > newest {
			newest = e.TimestampMs
		}
		placed := false
		for i, le := range histEdges {
			if e.DurationMs <= le {
				out.Histogram[i].Count++
				placed = true
				break
			}
		}
		if !placed {
			out.Histogram[len(histEdges)].Count++
		}
	}
	out.P50Ms = percentile(lats, 0.50)
	out.P99Ms = percentile(lats, 0.99)
	span := float64(newest-oldest) / 1000
	if span < 1 {
		span = 1
	}
	out.RPS = float64(len(evs)) / span
	out.TopPaths = topN(paths, 10)
	out.TopClients = topN(clients, 10)
	out.Geo = topN(geo, 20)
	out.BlockedByStage = topN(stages, 10)
	return out
}

// NodeStats is a 60s window for one node.
type NodeStats struct {
	RPS      float64 `json:"rps"`
	P50Ms    float64 `json:"p50_ms"`
	P99Ms    float64 `json:"p99_ms"`
	Requests int     `json:"requests"`
}

func (s *Service) NodeStats() map[string]NodeStats {
	cutoff := time.Now().Add(-onlineAfter).UnixMilli()
	s.mu.Lock()
	defer s.mu.Unlock()
	by := map[string][]float64{}
	for _, e := range s.live {
		if e.NodeID == "" || e.TimestampMs < cutoff {
			continue
		}
		by[e.NodeID] = append(by[e.NodeID], e.DurationMs)
	}
	out := map[string]NodeStats{}
	for id, lats := range by {
		out[id] = NodeStats{
			RPS:      float64(len(lats)) / onlineAfter.Seconds(),
			P50Ms:    percentile(append([]float64(nil), lats...), 0.50),
			P99Ms:    percentile(append([]float64(nil), lats...), 0.99),
			Requests: len(lats),
		}
	}
	return out
}

// Flush writes pending accumulators to Postgres.
func (s *Service) Flush(ctx context.Context) {
	s.mu.Lock()
	pending := s.pending
	s.pending = map[rollupKey]*rollupAcc{}
	geoPending := s.pendingGeo
	s.pendingGeo = map[geoKey]int64{}
	s.mu.Unlock()
	if s.st == nil {
		return
	}
	if len(pending) > 0 {
		hourly := make([]store.RollupRow, 0, len(pending))
		daily := make([]store.RollupRow, 0, len(pending))
		for k, acc := range pending {
			hourly = append(hourly, store.RollupRow{
				BucketStart: k.hour, HostID: k.host, Domain: k.domain,
				StatusClass: k.statusClass, BlockStage: k.blockStage,
				Count: acc.count, LatencySum: acc.latSum, BytesSum: acc.bytes,
			})
			daily = append(daily, store.RollupRow{
				BucketStart: k.day, HostID: k.host, Domain: k.domain,
				StatusClass: k.statusClass, BlockStage: k.blockStage,
				Count: acc.count, LatencySum: acc.latSum, BytesSum: acc.bytes,
			})
		}
		if err := s.st.UpsertHourly(ctx, hourly); err != nil {
			log.Printf("telemetry: hourly rollup: %v", err)
		}
		if err := s.st.UpsertDaily(ctx, daily); err != nil {
			log.Printf("telemetry: daily rollup: %v", err)
		}
	}
	if len(geoPending) > 0 {
		hourly := make([]store.GeoRollupRow, 0, len(geoPending))
		daily := make([]store.GeoRollupRow, 0, len(geoPending))
		for k, n := range geoPending {
			hourly = append(hourly, store.GeoRollupRow{
				BucketStart: k.hour, HostID: k.host, Country: k.country, Count: n,
			})
			daily = append(daily, store.GeoRollupRow{
				BucketStart: k.day, HostID: k.host, Country: k.country, Count: n,
			})
		}
		if err := s.st.UpsertGeoHourly(ctx, hourly); err != nil {
			log.Printf("telemetry: geo hourly: %v", err)
		}
		if err := s.st.UpsertGeoDaily(ctx, daily); err != nil {
			log.Printf("telemetry: geo daily: %v", err)
		}
	}
}

// FlushLog writes queued events to the request log.
func (s *Service) FlushLog(ctx context.Context) {
	s.mu.Lock()
	batch := s.pendingLog
	s.pendingLog = nil
	s.mu.Unlock()
	if n := s.logDropped.Swap(0); n > 0 {
		log.Printf("telemetry: request log fell behind, dropped %d events", n)
	}
	if s.st == nil || len(batch) == 0 {
		return
	}
	rows := make([]store.RequestLogRow, 0, len(batch))
	for _, e := range batch {
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		rows = append(rows, store.RequestLogRow{
			TS: time.UnixMilli(e.TimestampMs).UTC(), RequestID: e.ID, HostID: e.HostID,
			Domain: e.Domain, Method: e.Method, Path: e.Path, Status: int(e.Status),
			ClientIP: e.ClientIP, Country: e.Country, BlockStage: e.BlockStage,
			WAFAction: e.WAFAction, WAFRuleID: e.WAFRuleID, Event: b,
		})
	}
	if err := s.st.InsertRequestLog(ctx, rows); err != nil {
		log.Printf("telemetry: request log: %v (%d events lost)", err, len(rows))
	}
}

func (s *Service) prune(ctx context.Context) {
	if s.st == nil {
		return
	}
	now := time.Now().UTC()
	if err := s.st.PruneAnalytics(ctx, now); err != nil {
		log.Printf("telemetry: prune analytics: %v", err)
	}
	if err := s.st.PruneRequestLog(ctx, now, s.logKeep, s.securityKeep); err != nil {
		log.Printf("telemetry: prune request log: %v", err)
	}
	if err := s.st.PruneEnrollTokens(ctx, now); err != nil {
		log.Printf("telemetry: prune enroll tokens: %v", err)
	}
	if err := s.st.PruneRevokedSessions(ctx, now); err != nil {
		log.Printf("telemetry: prune revoked sessions: %v", err)
	}
	if err := s.st.PruneAudit(ctx, now); err != nil {
		log.Printf("telemetry: prune audit: %v", err)
	}
}

func nodeIDFromPeer(ctx context.Context) uuid.UUID {
	if p, ok := peer.FromContext(ctx); ok {
		if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			for _, chain := range ti.State.VerifiedChains {
				if len(chain) > 0 {
					if id, err := uuid.Parse(chain[0].Subject.CommonName); err == nil {
						return id
					}
				}
			}
		}
	}
	return uuid.Nil
}

func statusClass(status int32) int {
	if status <= 0 {
		return 0
	}
	return int(status / 100)
}

func normalizeStage(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none":
		return ""
	case "waf", "crowdsec", "ratelimit", "geo", "acl":
		return strings.ToLower(strings.TrimSpace(s))
	default:
		return ""
	}
}

func percentile(vals []float64, p float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sort.Float64s(vals)
	if p <= 0 {
		return vals[0]
	}
	if p >= 1 {
		return vals[len(vals)-1]
	}
	idx := int(float64(len(vals)-1) * p)
	return vals[idx]
}

func topN(m map[string]int, n int) []CountRow {
	out := make([]CountRow, 0, len(m))
	for k, c := range m {
		out = append(out, CountRow{Key: k, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
