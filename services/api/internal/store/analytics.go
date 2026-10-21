package store

import (
	"context"
	"fmt"
	"time"
)

const (
	// HourlyRetention is how long analytics_hourly rows are kept.
	HourlyRetention = 14 * 24 * time.Hour
	// DailyRetention is how long analytics_daily rows are kept.
	DailyRetention = 90 * 24 * time.Hour
	// AuditRetention is how long audit_events rows are kept.
	AuditRetention = 90 * 24 * time.Hour
)

// RollupRow is one aggregated analytics bucket (hourly or daily).
// Grain is (bucket, host, domain, status class, block stage) — path, country,
// and node stay on the live ring only.
type RollupRow struct {
	BucketStart time.Time `json:"bucket_start"`
	HostID      string    `json:"host_id"`
	Domain      string    `json:"domain"`
	StatusClass int       `json:"status_class"`
	BlockStage  string    `json:"block_stage"`
	Count       int64     `json:"count"`
	LatencySum  float64   `json:"latency_sum_ms"`
	BytesSum    int64     `json:"bytes_sum"`
}

// UpsertHourly adds a flush window into the hourly table.
func (s *Store) UpsertHourly(ctx context.Context, rows []RollupRow) error {
	return s.upsertRollups(ctx, "analytics_hourly", rows)
}

// UpsertDaily adds a flush window into the daily table.
func (s *Store) UpsertDaily(ctx context.Context, rows []RollupRow) error {
	return s.upsertRollups(ctx, "analytics_daily", rows)
}

func (s *Store) upsertRollups(ctx context.Context, table string, rows []RollupRow) error {
	if s == nil || s.pool == nil || len(rows) == 0 {
		return nil
	}
	q := `
		INSERT INTO ` + table + ` (
			bucket_start, host_id, domain, status_class, block_stage,
			count, latency_sum_ms, bytes_sum
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (bucket_start, host_id, domain, status_class, block_stage)
		DO UPDATE SET
			count = ` + table + `.count + EXCLUDED.count,
			latency_sum_ms = ` + table + `.latency_sum_ms + EXCLUDED.latency_sum_ms,
			bytes_sum = ` + table + `.bytes_sum + EXCLUDED.bytes_sum`
	for _, r := range rows {
		if _, err := s.pool.Exec(ctx, q,
			r.BucketStart, r.HostID, r.Domain, r.StatusClass, r.BlockStage,
			r.Count, r.LatencySum, r.BytesSum,
		); err != nil {
			return err
		}
	}
	return nil
}

// RollupGroup says what ListRollups sums away before returning rows.
type RollupGroup string

const (
	// RollupRaw is the stored grain: a row per bucket, host, domain, status
	// class and block stage.
	RollupRaw RollupGroup = ""
	// RollupByBucket sums hosts away: a row per bucket, status class and
	// block stage. The row count no longer grows with the number of hosts.
	RollupByBucket RollupGroup = "bucket"
	// RollupByHost sums buckets away: a row per host, status class and block
	// stage, busiest host first. bucket_start is the host's earliest bucket
	// in the range.
	RollupByHost RollupGroup = "host"
)

// RollupRowCap is the most rows one ListRollups call returns.
const RollupRowCap = 2000

// ListRollups returns hourly or daily rows with from <= bucket_start < to,
// newest bucket first (busiest host first for RollupByHost). hostID empty
// means every host. truncated reports that more rows matched than
// RollupRowCap: the ones left out are the oldest buckets (the quietest hosts
// for RollupByHost), so a caller must not read their absence as zero.
func (s *Store) ListRollups(ctx context.Context, daily bool, from, to time.Time, hostID string, group RollupGroup) (out []RollupRow, truncated bool, err error) {
	if s == nil || s.pool == nil {
		return nil, false, nil
	}
	table := "analytics_hourly"
	if daily {
		table = "analytics_daily"
	}
	where := ` WHERE bucket_start >= $1 AND bucket_start < $2`
	args := []any{from, to}
	if hostID != "" {
		where += ` AND host_id = $3`
		args = append(args, hostID)
	}
	var q string
	switch group {
	case RollupByBucket:
		q = `
		SELECT bucket_start, '' AS host_id, '' AS domain, status_class, block_stage,
		       SUM(count)::bigint, SUM(latency_sum_ms), SUM(bytes_sum)::bigint
		FROM ` + table + where + `
		GROUP BY bucket_start, status_class, block_stage
		ORDER BY bucket_start DESC, status_class, block_stage`
	case RollupByHost:
		q = `
		SELECT MIN(bucket_start), host_id, MIN(domain) AS domain, status_class, block_stage,
		       SUM(count)::bigint, SUM(latency_sum_ms), SUM(bytes_sum)::bigint
		FROM ` + table + where + `
		GROUP BY host_id, status_class, block_stage
		ORDER BY SUM(SUM(count)) OVER (PARTITION BY host_id) DESC, host_id, status_class, block_stage`
	default:
		q = `
		SELECT bucket_start, host_id, domain, status_class, block_stage,
		       count, latency_sum_ms, bytes_sum
		FROM ` + table + where + `
		ORDER BY bucket_start DESC`
	}
	// One past the cap, so a full page can be told from a cut one.
	q += fmt.Sprintf(` LIMIT %d`, RollupRowCap+1)
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out = []RollupRow{}
	for rows.Next() {
		var r RollupRow
		if err := rows.Scan(&r.BucketStart, &r.HostID, &r.Domain,
			&r.StatusClass, &r.BlockStage, &r.Count, &r.LatencySum, &r.BytesSum); err != nil {
			return nil, false, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(out) > RollupRowCap {
		return out[:RollupRowCap], true, nil
	}
	return out, false, nil
}

// PruneAnalytics deletes hourly and daily buckets older than the retention windows.
func (s *Store) PruneAnalytics(ctx context.Context, now time.Time) error {
	if s == nil || s.pool == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM analytics_hourly WHERE bucket_start < $1`, now.Add(-HourlyRetention)); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx,
		`DELETE FROM analytics_daily WHERE bucket_start < $1`, now.Add(-DailyRetention))
	if err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM analytics_geo_hourly WHERE bucket_start < $1`, now.Add(-HourlyRetention)); err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`DELETE FROM analytics_geo_daily WHERE bucket_start < $1`, now.Add(-DailyRetention))
	return err
}

// GeoRollupRow is one country bucket. Separate from the main grain so ISO
// codes do not explode the host/domain/stage primary key.
type GeoRollupRow struct {
	BucketStart time.Time `json:"bucket_start"`
	HostID      string    `json:"host_id"`
	Country     string    `json:"country"`
	Count       int64     `json:"count"`
}

func (s *Store) UpsertGeoHourly(ctx context.Context, rows []GeoRollupRow) error {
	return s.upsertGeo(ctx, "analytics_geo_hourly", rows)
}

func (s *Store) UpsertGeoDaily(ctx context.Context, rows []GeoRollupRow) error {
	return s.upsertGeo(ctx, "analytics_geo_daily", rows)
}

func (s *Store) upsertGeo(ctx context.Context, table string, rows []GeoRollupRow) error {
	if s == nil || s.pool == nil || len(rows) == 0 {
		return nil
	}
	q := `
		INSERT INTO ` + table + ` (bucket_start, host_id, country, count)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (bucket_start, host_id, country)
		DO UPDATE SET count = ` + table + `.count + EXCLUDED.count`
	for _, r := range rows {
		if _, err := s.pool.Exec(ctx, q, r.BucketStart, r.HostID, r.Country, r.Count); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListGeo(ctx context.Context, daily bool, from, to time.Time, hostID string) ([]GeoRollupRow, error) {
	if s == nil || s.pool == nil {
		return nil, nil
	}
	table := "analytics_geo_hourly"
	if daily {
		table = "analytics_geo_daily"
	}
	q := `
		SELECT bucket_start, host_id, country, count
		FROM ` + table + `
		WHERE bucket_start >= $1 AND bucket_start < $2`
	args := []any{from, to}
	if hostID != "" {
		q += ` AND host_id = $3`
		args = append(args, hostID)
	}
	q += ` ORDER BY bucket_start DESC LIMIT 4000`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GeoRollupRow{}
	for rows.Next() {
		var r GeoRollupRow
		if err := rows.Scan(&r.BucketStart, &r.HostID, &r.Country, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
