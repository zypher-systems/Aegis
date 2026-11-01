package telemetry

import (
	"context"
	"crypto/tls"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

// PushLoop drains the ring and streams events over mTLS. Reconnects forever.
func PushLoop(ctx context.Context, addr string, tlsCfg *tls.Config, em *Emitter) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := pushOnce(ctx, addr, tlsCfg, em)
		if ctx.Err() != nil {
			return
		}
		log.Printf("telemetry push disconnected: %v; reconnecting in %s", err, backoff)
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

func pushOnce(ctx context.Context, addr string, tlsCfg *tls.Config, em *Emitter) error {
	// The stream lives on its own context so the last events can still be
	// sent after ctx ends (shutdown); keepalive covers a dead server.
	streamCtx, cancelStream := context.WithCancel(context.Background())
	defer cancelStream()
	conn, err := grpc.DialContext(streamCtx, addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                2 * time.Minute,
			Timeout:             20 * time.Second,
			PermitWithoutStream: false,
		}),
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := aegisv1.NewTelemetryServiceClient(conn)
	stream, err := client.Push(streamCtx)
	if err != nil {
		return err
	}
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Final flush: whatever the drain produced, within a short bound.
			deadline := time.AfterFunc(3*time.Second, cancelStream)
			for _, ev := range em.Drain(4096) {
				if err := stream.Send(ev); err != nil {
					break
				}
			}
			_, _ = stream.CloseAndRecv()
			deadline.Stop()
			return ctx.Err()
		case <-stream.Context().Done():
			// The API went away (restart, network). Reconnect now rather than
			// on the next send, which would write into the dead stream.
			return stream.Context().Err()
		case <-ticker.C:
			batch := em.Drain(128)
			for i, ev := range batch {
				if err := stream.Send(ev); err != nil {
					em.Requeue(batch[i:])
					return err
				}
			}
		}
	}
}
