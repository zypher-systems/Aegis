// Command aegis-proxy is the data plane: it enrolls with the control plane,
// maintains an mTLS config stream, and serves the HTTP/HTTPS edge.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/redis/go-redis/v9"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/internal/healthcheck"
	"github.com/zypher-systems/aegis/services/proxy/internal/config"
	"github.com/zypher-systems/aegis/services/proxy/internal/configstore"
	"github.com/zypher-systems/aegis/services/proxy/internal/identity"
	"github.com/zypher-systems/aegis/services/proxy/internal/server"
	"github.com/zypher-systems/aegis/services/proxy/internal/telemetry"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC | log.Lshortfile)
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		addr := os.Getenv("AEGIS_HTTP_ADDR")
		if addr == "" {
			addr = ":80"
		}
		// Readiness: a config is loaded and the node is not revoked.
		healthcheck.Exit(addr, "/readyz")
		return
	}
	if err := run(); err != nil {
		log.Fatalf("aegis-proxy: %v", err)
	}
}

func run() error {
	cfg := config.Load()

	// sigCtx ends on SIGTERM and starts the drain; ctx (the loops') ends
	// once the drain is over, so telemetry and the config stream outlive
	// in-flight requests.
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, stopLoops := context.WithCancel(context.Background())
	defer stopLoops()

	// Identity: load persisted or enroll.
	id, err := identity.LoadOrEnroll(sigCtx, cfg.StateDir, cfg.ControlPlane, cfg.EnrollToken, cfg.NodeName, cfg.Version)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	log.Printf("node identity ready (id=%s, cert expires %s)", id.NodeID, id.ExpiresAt().Format(time.RFC3339))
	// Renew the client certificate from 30 days out so the node never falls
	// off the control plane when it expires.
	go id.RenewLoop(ctx, cfg.NodePlane, cfg.Version)

	snapKey, err := configstore.DeriveSnapshotKey(id.KeyPEM)
	if err != nil {
		return fmt.Errorf("snapshot key: %w", err)
	}

	var rdb *redis.Client
	if cfg.RedisAddr != "" {
		rdb = redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
		if err := rdb.Ping(ctx).Err(); err != nil {
			log.Printf("proxy: redis %s: %v (rate limit falls back to local)", cfg.RedisAddr, err)
			rdb.Close()
			rdb = nil
		}
	}
	server.LoadErrorPage(os.Getenv("AEGIS_ERROR_PAGE"))
	em := telemetry.NewEmitter()
	srv := server.NewWithOptions(server.Options{
		Redis: rdb, GeoIPMMDB: cfg.GeoIPMMDB, Telemetry: em, NodeID: id.NodeID,
		StateDir: cfg.StateDir, SnapshotKey: snapKey, TrustedProxyCIDRs: cfg.TrustedProxyCIDRs,
		AccessLog: cfg.AccessLog, UnknownHost: cfg.UnknownHost,
	})
	if snap, err := configstore.Load(cfg.StateDir, snapKey); err == nil {
		srv.Apply(snap)
		log.Printf("proxy: loaded last-known-good config v%d", snap.GetVersion())
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Printf("proxy: last-known-good: %v", err)
	}

	// Start config stream loop (reconnects forever).
	go watchConfig(ctx, cfg, id, srv)
	go reportProblems(ctx, cfg, id, srv)
	pushDone := make(chan struct{})
	go func() {
		telemetry.PushLoop(ctx, cfg.NodePlane, id.TLSConfig("aegis-api"), em)
		close(pushDone)
	}()
	var tracker server.ConnTracker

	// HTTP listener (challenges, redirects, plain hosts).
	httpSrv := edgeHTTPServer(cfg.HTTPAddr, srv, nil)
	httpLn, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("http listen: %w", err)
	}
	httpLn = tracker.TrackListener(httpLn)
	go func() {
		log.Printf("HTTP edge listening on %s", cfg.HTTPAddr)
		if err := httpSrv.Serve(httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("http serve: %v", err)
		}
	}()

	// HTTPS listener with SNI-based cert selection.
	httpsSrv := edgeHTTPServer(cfg.HTTPSAddr, srv, srv.TLSConfig())
	httpsLn, err := net.Listen("tcp", cfg.HTTPSAddr)
	if err != nil {
		return fmt.Errorf("https listen: %w", err)
	}
	tlsLn := tls.NewListener(tracker.TrackListener(httpsLn), httpsSrv.TLSConfig)
	go func() {
		log.Printf("HTTPS edge listening on %s", cfg.HTTPSAddr)
		if err := httpsSrv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("https serve: %v", err)
		}
	}()

	<-sigCtx.Done()
	// compose gives us 30 s (stop_grace_period). Stop accepting, let
	// in-flight requests finish, give long-lived connections (WebSockets,
	// streams) the rest of the budget, then close what is left.
	log.Printf("shutting down: draining %d connections", tracker.Len())
	drainCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	srv.CloseStreams()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = httpSrv.Shutdown(drainCtx) }()
	go func() { defer wg.Done(); _ = httpsSrv.Shutdown(drainCtx) }()
	wg.Wait()
	if n := tracker.Drain(drainCtx); n > 0 {
		log.Printf("shutting down: closed %d connections still open after the drain", n)
	}
	// Loops end last so the final telemetry batch covers the drain.
	stopLoops()
	select {
	case <-pushDone:
	case <-time.After(3 * time.Second):
	}
	log.Printf("shutdown complete")
	return nil
}

// maxConfigMessage bounds one config snapshot on the wire (64 MiB, roughly
// ten thousand certificates); the API sets the same limit.
const maxConfigMessage = 64 << 20

func edgeHTTPServer(addr string, h http.Handler, tlsCfg *tls.Config) *http.Server {
	return &http.Server{
		Addr:      addr,
		Handler:   h,
		TLSConfig: tlsCfg,
		// No whole-request Read/WriteTimeout: those cut long downloads,
		// uploads and event streams at a fixed mark. Each host applies an
		// idle deadline instead (no bytes either way for N seconds).
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          server.EdgeErrorLog(),
	}
}

// watchConfig maintains a resilient mTLS config stream, applying snapshots as
// they arrive. Reconnects with backoff until ctx is cancelled.
func watchConfig(ctx context.Context, cfg *config.Config, id *identity.Identity, srv *server.Server) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := streamOnce(ctx, cfg, id, srv)
		if ctx.Err() != nil {
			return
		}
		if status.Code(err) == codes.Unauthenticated && strings.Contains(err.Error(), "revoked") {
			// The operator revoked this node. Stop serving, forget the
			// config and the identity; a restart with a token re-enrols.
			srv.Disable("the control plane revoked this node's certificate")
			identity.Wipe(cfg.StateDir)
			return
		}
		log.Printf("config stream disconnected: %v; reconnecting in %s", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func streamOnce(ctx context.Context, cfg *config.Config, id *identity.Identity, srv *server.Server) error {
	tlsCfg := id.TLSConfig("aegis-api")
	conn, err := grpc.DialContext(ctx, cfg.NodePlane,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		// A snapshot carries every certificate; the gRPC default of 4 MB
		// would silently freeze config at a few hundred certificates.
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxConfigMessage)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                2 * time.Minute,
			Timeout:             20 * time.Second,
			PermitWithoutStream: false,
		}),
	)
	if err != nil {
		return fmt.Errorf("dial node plane: %w", err)
	}
	defer conn.Close()

	client := aegisv1.NewConfigServiceClient(conn)
	stream, err := client.Watch(ctx, &aegisv1.WatchRequest{
		NodeId:       id.NodeID,
		LastVersion:  srv.Version(),
		AgentVersion: cfg.Version,
	})
	if err != nil {
		return fmt.Errorf("watch: %w", err)
	}
	for {
		u, err := stream.Recv()
		if err != nil {
			return err
		}
		srv.Apply(u)
	}
}

// reportProblems tells the control plane what is wrong on this node whenever
// that changes (checked every 10 s, so an upstream outage reaches the
// operator within about 20 s of the second failed probe), and at least every
// 10 minutes so a restarted API catches up.
func reportProblems(ctx context.Context, cfg *config.Config, id *identity.Identity, srv *server.Server) {
	last := "\x00"
	lastSent := time.Time{}
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		fp := srv.ProblemsFingerprint()
		if fp == last && time.Since(lastSent) < 10*time.Minute {
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		conn, err := grpc.DialContext(rctx, cfg.NodePlane,
			grpc.WithTransportCredentials(credentials.NewTLS(id.TLSConfig("aegis-api"))), grpc.WithBlock())
		if err == nil {
			_, err = aegisv1.NewConfigServiceClient(conn).Report(rctx, &aegisv1.NodeReport{Problems: srv.Problems()})
			conn.Close()
		}
		cancel()
		if err != nil {
			log.Printf("proxy: report problems: %v", err)
			continue
		}
		last, lastSent = fp, time.Now()
	}
}
