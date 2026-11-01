package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// RequestLogRow is one proxied request. The columns are what the dashboard
// filters on; Event is the full telemetry event as JSON.
type RequestLogRow struct {
	TS         time.Time
	RequestID  string
	HostID     string
	Domain     string
	Method     string
	Path       string
	Status     int
	ClientIP   string
	Country    string
	BlockStage string
	WAFAction  string
	WAFRuleID  string
	Event      json.RawMessage
}

// InsertRequestLog bulk-loads rows with COPY.
func (s *Store) InsertRequestLog(ctx context.Context, rows []RequestLogRow) error {
	if s == nil || s.pool == nil || len(rows) == 0 {
		return nil
	}
	_, err := s.pool.CopyFrom(ctx, pgx.Identifier{"request_log"},
		[]string{"ts", "request_id", "host_id", "domain", "method", "path", "status",
			"client_ip", "country", "block_stage", "waf_action", "waf_rule_id", "event"},
		pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
			r := rows[i]
			return []any{r.TS, r.RequestID, r.HostID, r.Domain, r.Method, r.Path, r.Status,
				r.ClientIP, r.Country, r.BlockStage, r.WAFAction, r.WAFRuleID, string(r.Event)}, nil
		}))
	return err
}

// RequestLogQuery filters the request log. Empty fields match everything.
type RequestLogQuery struct {
	From, To  time.Time
	HostID    string
	Country   string
	ClientIP  string
	Stage     string // a block stage (waf, crowdsec, …)
	Outcome   string // "blocked", "flagged" (blocked or WAF-detected), "served"
	RuleID    string // a CRS rule that matched
	Status    int    // a status class: 2, 3, 4, 5
	Method    string
	Path      string // exact path
	Search    string // substring of path or domain, or an exact IP / request id
	RequestID string
	Cursor    string // from a previous page's Next
	Limit     int
}

// RequestLogCountCap bounds the count query; the dashboard shows "10,000+".
const RequestLogCountCap = 10_000

// RequestLogPage is one page, newest first. Next is empty on the last page.
// Count is the number of matching rows, capped at RequestLogCountCap+1.
type RequestLogPage struct {
	Events []json.RawMessage
	Next   string
	Count  int
}

// ListRequestLog returns matching requests newest first, paged by cursor.
func (s *Store) ListRequestLog(ctx context.Context, q RequestLogQuery) (RequestLogPage, error) {
	out := RequestLogPage{Events: []json.RawMessage{}}
	if s == nil || s.pool == nil {
		return out, nil
	}
	where, args := requestLogWhere(q)

	var cnt int
	countSQL := `SELECT count(*) FROM (SELECT 1 FROM request_log WHERE ` + where +
		` LIMIT ` + strconv.Itoa(RequestLogCountCap+1) + `) t`
	if err := s.pool.QueryRow(ctx, countSQL, args...).Scan(&cnt); err != nil {
		return out, err
	}
	out.Count = cnt

	if ts, seq, ok := parseRequestCursor(q.Cursor); ok {
		args = append(args, ts, seq)
		where += fmt.Sprintf(` AND (ts, seq) < ($%d, $%d)`, len(args)-1, len(args))
	}
	limit := q.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `SELECT ts, seq, event FROM request_log WHERE `+where+
		` ORDER BY ts DESC, seq DESC LIMIT `+strconv.Itoa(limit+1), args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	type key struct {
		ts  time.Time
		seq int64
	}
	var keys []key
	for rows.Next() {
		var k key
		var ev []byte
		if err := rows.Scan(&k.ts, &k.seq, &ev); err != nil {
			return out, err
		}
		keys = append(keys, k)
		out.Events = append(out.Events, json.RawMessage(ev))
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(out.Events) > limit {
		out.Events = out.Events[:limit]
		last := keys[limit-1]
		out.Next = fmt.Sprintf("%d.%d", last.ts.UnixMicro(), last.seq)
	}
	return out, nil
}

func requestLogWhere(q RequestLogQuery) (string, []any) {
	var conds []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if !q.From.IsZero() {
		add("ts >= $%d", q.From)
	}
	if !q.To.IsZero() {
		add("ts < $%d", q.To)
	}
	if q.HostID != "" {
		add("host_id = $%d", q.HostID)
	}
	if q.Country != "" {
		add("country = $%d", strings.ToUpper(q.Country))
	}
	if q.ClientIP != "" {
		add("client_ip = $%d", q.ClientIP)
	}
	if q.Stage != "" {
		add("block_stage = $%d", q.Stage)
	}
	switch q.Outcome {
	case "blocked":
		conds = append(conds, "block_stage <> ''")
	case "flagged":
		conds = append(conds, "(block_stage <> '' OR waf_action <> '')")
	case "served":
		conds = append(conds, "block_stage = ''")
	}
	if q.RuleID != "" {
		args = append(args, q.RuleID)
		n := len(args)
		conds = append(conds, fmt.Sprintf(
			`(waf_rule_id = $%d OR event->'waf_matches' @> jsonb_build_array(jsonb_build_object('rule_id', $%d::text)))`, n, n))
	}
	if q.Status >= 1 && q.Status <= 5 {
		add("status >= $%d", q.Status*100)
		add("status < $%d", q.Status*100+100)
	}
	if q.Method != "" {
		add("method = $%d", strings.ToUpper(q.Method))
	}
	if q.RequestID != "" {
		add("request_id = $%d", q.RequestID)
	}
	if q.Path != "" {
		add("path = $%d", q.Path)
	}
	if s := strings.TrimSpace(q.Search); s != "" {
		args = append(args, s, "%"+escapeLike(s)+"%")
		n := len(args)
		conds = append(conds, fmt.Sprintf(
			`(client_ip = $%d OR request_id = $%d OR path ILIKE $%d OR domain ILIKE $%d)`, n-1, n-1, n, n))
	}
	if len(conds) == 0 {
		return "TRUE", args
	}
	return strings.Join(conds, " AND "), args
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func parseRequestCursor(c string) (time.Time, int64, bool) {
	a, b, ok := strings.Cut(c, ".")
	if !ok {
		return time.Time{}, 0, false
	}
	us, err1 := strconv.ParseInt(a, 10, 64)
	seq, err2 := strconv.ParseInt(b, 10, 64)
	if err1 != nil || err2 != nil {
		return time.Time{}, 0, false
	}
	return time.UnixMicro(us).UTC(), seq, true
}

// RecentRequestLog returns the newest events, newest first.
func (s *Store) RecentRequestLog(ctx context.Context, limit int) ([]json.RawMessage, error) {
	if s == nil || s.pool == nil {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT event FROM request_log ORDER BY ts DESC, seq DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var ev []byte
		if err := rows.Scan(&ev); err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(ev))
	}
	return out, rows.Err()
}

// PruneRequestLog drops served requests older than allFor and blocked or
// flagged ones older than securityFor.
func (s *Store) PruneRequestLog(ctx context.Context, now time.Time, allFor, securityFor time.Duration) error {
	if s == nil || s.pool == nil {
		return nil
	}
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM request_log WHERE ts < $1 AND block_stage = '' AND waf_action = ''`, now.Add(-allFor)); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM request_log WHERE ts < $1`, now.Add(-securityFor))
	return err
}

// WAFFinding is one CRS rule's hits in the request log with a sample.
type WAFFinding struct {
	RuleID      string    `json:"rule_id"`
	Hits        int64     `json:"hits"`
	Blocked     int64     `json:"blocked"`
	Clients     int64     `json:"clients"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Hosts       []string  `json:"hosts"`
	Paths       []string  `json:"paths"`
	SampleWhere string    `json:"sample_where"` // e.g. REQUEST_COOKIES:session
	SampleValue string    `json:"sample_value"`
	HostID      string    `json:"host_id"` // host of the newest hit
	Path        string    `json:"path"`    // path of the newest hit
}

// WAFFindings aggregates flagged and blocked requests by matched rule since
// from. Rows from nodes older than 1.7.1 (no per-match detail) count under
// their top rule.
func (s *Store) WAFFindings(ctx context.Context, from time.Time, hostID string) ([]WAFFinding, error) {
	out := []WAFFinding{}
	if s == nil || s.pool == nil {
		return out, nil
	}
	args := []any{from}
	hostCond := ""
	if hostID != "" {
		args = append(args, hostID)
		hostCond = " AND host_id = $2"
	}
	rows, err := s.pool.Query(ctx, `
		WITH m AS (
			SELECT r.ts, r.host_id, r.domain, r.path, r.client_ip, r.block_stage,
			       x->>'rule_id' AS rule_id,
			       COALESCE(x->>'variable','') || CASE WHEN COALESCE(x->>'key','') <> '' THEN ':' || (x->>'key') ELSE '' END AS whr,
			       LEFT(COALESCE(x->>'value',''), 160) AS val
			FROM request_log r,
			     jsonb_array_elements(COALESCE(NULLIF(r.event->'waf_matches','null'),
			         jsonb_build_array(jsonb_build_object('rule_id', r.waf_rule_id)))) x
			WHERE r.waf_action <> '' AND r.ts >= $1`+hostCond+`
		)
		SELECT rule_id, COUNT(*), COUNT(*) FILTER (WHERE block_stage <> ''), COUNT(DISTINCT client_ip),
		       MIN(ts), MAX(ts),
		       (ARRAY_AGG(DISTINCT domain))[1:6],
		       (ARRAY(SELECT DISTINCT p FROM UNNEST(ARRAY_AGG(path ORDER BY ts DESC)) p LIMIT 5)),
		       (ARRAY_AGG(whr ORDER BY ts DESC))[1], (ARRAY_AGG(val ORDER BY ts DESC))[1],
		       (ARRAY_AGG(host_id ORDER BY ts DESC))[1], (ARRAY_AGG(path ORDER BY ts DESC))[1]
		FROM m WHERE rule_id <> ''
		GROUP BY rule_id ORDER BY 2 DESC LIMIT 200`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var f WAFFinding
		if err := rows.Scan(&f.RuleID, &f.Hits, &f.Blocked, &f.Clients, &f.FirstSeen, &f.LastSeen,
			&f.Hosts, &f.Paths, &f.SampleWhere, &f.SampleValue, &f.HostID, &f.Path); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
