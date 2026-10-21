// Command aegis-api is the control plane: REST API for the dashboard and a
// gRPC plane for enrollment, config push, and telemetry.
//
// Two gRPC listeners are used:
//   - enrollment listener (TLS, no client cert): serves only EnrollmentService,
//     authenticated by a one-time token. This is how new nodes get an identity.
//   - node listener (mTLS, client cert required): serves ConfigService and
//     TelemetryService for already-enrolled nodes.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/internal/healthcheck"
	"github.com/zypher-systems/aegis/services/api/internal/alerts"
	"github.com/zypher-systems/aegis/services/api/internal/auth"
	"github.com/zypher-systems/aegis/services/api/internal/ca"
	"github.com/zypher-systems/aegis/services/api/internal/certsvc"
	"github.com/zypher-systems/aegis/services/api/internal/config"
	"github.com/zypher-systems/aegis/services/api/internal/configsvc"
	"github.com/zypher-systems/aegis/services/api/internal/crypto"
	"github.com/zypher-systems/aegis/services/api/internal/enroll"
	"github.com/zypher-systems/aegis/services/api/internal/httpapi"
	"github.com/zypher-systems/aegis/services/api/internal/store"
	"github.com/zypher-systems/aegis/services/api/internal/telemetry"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC | log.Lshortfile)
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		addr := os.Getenv("AEGIS_HTTP_ADDR")
		if addr == "" {
			addr = ":8080"
		}
		healthcheck.Exit(addr, "/api/readyz")
		return
	}
	if err := run(); err != nil {
		log.Fatalf("aegis-api: %v", err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	env, err := crypto.NewEnvelope(cfg.SecretKey)
	if err != nil {
		return fmt.Errorf("envelope: %w", err)
	}

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer st.Close()
	log.Printf("connected to postgres, migrations applied")

	if seeded, err := st.SeedCrowdSecLAPI(ctx, cfg.CrowdSecURL, cfg.CrowdSecKey, env.Seal, env.Open); err != nil {
		log.Printf("crowdsec lapi seed: %v", err)
	} else if seeded {
		log.Printf("crowdsec lapi seeded from env")
	}
	if err := st.SeedCrowdSecFirewall(ctx, true, env.Seal, env.Open); err != nil {
		log.Printf("crowdsec firewall seed: %v", err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	if err := rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	defer rdb.Close()
	log.Printf("connected to redis")

	// Internal CA (encrypted at rest).
	caInst, err := ca.LoadOrInit(
		func(k string) ([]byte, error) { return st.GetSetting(ctx, k, env.Open) },
		func(k string, v []byte) error { return st.SetSetting(ctx, k, v, env.Seal) },
	)
	if err != nil {
		return fmt.Errorf("internal ca: %w", err)
	}
	log.Printf("internal CA ready")

	// Config push service.
	cfgSvc := configsvc.New(st, env, nil)
	cfgSvc.EnableRenewal(caInst, cfg.NodeCertTTL)
	// Operator notices and the webhook behind them.
	alertsC := alerts.New(st, env)
	cfgSvc.SetNotifier(alertsC)
	go cfgSvc.NodeHealthLoop(ctx)
	cfgSvc.SetEnvTrustedCIDRs(cfg.TrustedProxyCIDRs)

	certs := certsvc.New(st, env, caInst, cfg.SelfSigned, certsvc.ACMEConfig{
		Directory:       cfg.ACMEDirectory,
		Email:           cfg.ACMEEmail,
		SkipTLS:         cfg.ACMESkipTLS,
		CloudflareToken: cfg.CloudflareToken,
	}, cfgSvc.Bump)
	cfgSvc.SetChallengeProvider(certs)
	go certs.RenewLoop(ctx)

	// Session manager (HMAC-signed cookies).
	// Sessions sign with a key derived from the master key, never the master
	// key itself, so a leaked session key cannot open anything at rest.
	sm := auth.NewSessionManager(auth.SessionKey(cfg.SecretKey), 7*24*time.Hour)

	// Server TLS identity for the gRPC plane, signed by the internal CA.
	serverCert, serverKey, err := caInst.IssueServerCert(
		[]string{"aegis-api", "localhost", "api"}, 365*24*time.Hour)
	if err != nil {
		return fmt.Errorf("issue grpc server cert: %w", err)
	}
	serverPair, err := tlsX509KeyPair(serverCert, serverKey)
	if err != nil {
		return fmt.Errorf("grpc server keypair: %w", err)
	}

	// --- Enrollment listener (TLS, no client cert; token-authenticated) ---
	enrollTLS := tlsConfigForServer(serverPair)
	enrollTLS.ClientAuth = tlsNoClientCert
	enrollSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(enrollTLS)))
	enrollSvc := enroll.New(st, caInst, func(ctx context.Context) (string, error) {
		b, err := st.GetSetting(ctx, store.SettingEnrollToken, env.Open)
		if err == nil && len(b) > 0 {
			return string(b), nil
		}
		return cfg.EnrollToken, nil
	}, cfg.NodeCertTTL, rdb)
	// Enrolment hands a node every certificate key: it is audited and
	// announced, so an unexpected one is noticed.
	enrollSvc.Tokens = st
	enrollSvc.OnEnrolled = func(ctx context.Context, id uuid.UUID, name, ip, version string) {
		_ = st.InsertAudit(ctx, &store.AuditEvent{
			ActorEmail: "system", Action: "enroll", ResourceType: "node", ResourceID: id.String(),
			Summary: map[string]any{"name": name, "ip": ip, "agent_version": version},
		})
		alertsC.Info("Node "+name+" enrolled", "A new proxy node enrolled from "+ip+" (agent "+version+"). If you did not start it, revoke it on the Nodes page and rotate the enrolment token.")
	}
	aegisv1.RegisterEnrollmentServiceServer(enrollSrv, enrollSvc)
	enrollLn, err := net.Listen("tcp", cfg.EnrollAddr)
	if err != nil {
		return fmt.Errorf("enroll listen: %w", err)
	}
	go func() {
		log.Printf("enrollment (TLS, token) listening on %s", cfg.EnrollAddr)
		if err := enrollSrv.Serve(enrollLn); err != nil {
			log.Printf("enroll serve: %v", err)
		}
	}()

	// --- Node listener (mTLS, client cert required): config + telemetry ---
	nodeTLS := tlsConfigForServer(serverPair)
	nodeTLS.ClientAuth = tlsRequireAndVerifyClientCert
	nodeTLS.ClientCAs = caInst.CertPool()
	rejectRevokedClientCerts(nodeTLS, st.SerialRevoked)
	// Snapshots carry every certificate: 64 MiB matches the proxy's limit.
	nodeSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(nodeTLS)),
		grpc.MaxRecvMsgSize(64<<20), grpc.MaxSendMsgSize(64<<20))
	tel := telemetry.New(telemetry.Options{
		Store: st, Redis: rdb, GeoIPMMDB: cfg.GeoIPMMDB,
		TouchNode:  func(ctx context.Context, id uuid.UUID) { _ = st.TouchNode(ctx, id) },
		RequestLog: cfg.RequestLog, LogRetention: cfg.RequestLogRetention,
		SecurityRetention: cfg.SecurityLogRetention,
	})
	tel.Hydrate(ctx)
	go tel.Start(ctx)
	aegisv1.RegisterConfigServiceServer(nodeSrv, cfgSvc)
	aegisv1.RegisterTelemetryServiceServer(nodeSrv, tel)
	nodeLn, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		return fmt.Errorf("node grpc listen: %w", err)
	}
	go func() {
		log.Printf("node gRPC (mTLS) listening on %s", cfg.GRPCAddr)
		if err := nodeSrv.Serve(nodeLn); err != nil {
			log.Printf("node grpc serve: %v", err)
		}
	}()

	// --- HTTP plane (REST for dashboard) ---
	apiSrv := httpapi.New(httpapi.Deps{
		Store: st, Sessions: sm, OnChange: cfgSvc.Bump, Certs: certs,
		Redis: rdb, PublicOrigin: cfg.PublicOrigin, Envelope: env,
		Telemetry: tel, GeoIPPath: cfg.GeoIPMMDB,
		TrustedProxyCIDRs:       loadTrustedProxyCIDRs(ctx, st, env, cfg.TrustedProxyCIDRs),
		OnRevoke:                cfgSvc.Kick,
		CrowdSecControlDir:      cfg.CrowdSecControlDir,
		CrowdSecMachineID:       cfg.CrowdSecMachineID,
		CrowdSecMachinePassword: cfg.CrowdSecMachinePassword,
		Version:                 cfg.Version,
		Alerts:                  alertsC,
		MetricsToken:            cfg.MetricsToken,
		ConfigVersion:           cfgSvc.Version,
	})
	certs.SetNotifier(alertsC)
	// Older installs raised a license notice. Clear it so it does not linger
	// after the gate is gone.
	alertsC.Clear(ctx, "license", "state")

	httpSrv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           apiSrv.Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("HTTP API listening on %s", cfg.HTTPAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("http serve: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutting down")
	// compose gives us 30 s (stop_grace_period); finish well inside it.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// End node streams first so proxies start reconnecting (they keep their
	// last-known-good config meanwhile), then drain REST and gRPC together.
	// GracefulStop alone would wait forever on a stream that never ends.
	cfgSvc.Close()
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); gracefulStop(shutdownCtx, enrollSrv) }()
	go func() { defer wg.Done(); gracefulStop(shutdownCtx, nodeSrv) }()
	var httpErr error
	go func() { defer wg.Done(); httpErr = httpSrv.Shutdown(shutdownCtx) }()
	wg.Wait()
	// Anything nodes sent while we drained, and any alert still in flight.
	tel.Flush(context.Background())
	tel.FlushLog(context.Background())
	alertsC.Wait()
	log.Printf("shutdown complete")
	return httpErr
}

// gracefulStop lets in-flight RPCs finish until ctx expires, then forces.
func gracefulStop(ctx context.Context, srv *grpc.Server) {
	done := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		srv.Stop()
	}
}

func loadTrustedProxyCIDRs(ctx context.Context, st *store.Store, env *crypto.Envelope, fallback []string) []string {
	if env == nil {
		return fallback
	}
	raw, err := st.GetSetting(ctx, store.SettingTrustedProxyCIDRs, env.Open)
	if err != nil {
		return fallback
	}
	var tp struct {
		CIDRs []string `json:"cidrs"`
	}
	if json.Unmarshal(raw, &tp) != nil {
		return fallback
	}
	return tp.CIDRs
}
