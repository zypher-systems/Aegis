package server

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

const (
	udpIdle       = 60 * time.Second
	udpSessionCap = 2048
)

// defaultTCPIdle is the idle timeout on TCP stream sessions (matches UDP).
const defaultTCPIdle = 60 * time.Second

type streamKey struct {
	proto string
	port  uint32
}

type streamSpec struct {
	key       streamKey
	upstreams []string
	acl       *aegisv1.AccessList
	tcpIdle   time.Duration
}

func (s streamSpec) equal(o streamSpec) bool {
	if s.key != o.key || !proto.Equal(s.acl, o.acl) {
		return false
	}
	if len(s.upstreams) != len(o.upstreams) {
		return false
	}
	for i := range s.upstreams {
		if s.upstreams[i] != o.upstreams[i] {
			return false
		}
	}
	return true
}

type streamListener struct {
	cancel context.CancelFunc
	spec   streamSpec
}

type streamManager struct {
	mu     sync.Mutex
	live   map[streamKey]*streamListener
	closed bool
	// tcpIdle is copied into each listener's spec, so sessions never read
	// shared state. Tests shorten it before the first Sync.
	tcpIdle time.Duration
}

func newStreamManager() *streamManager {
	return &streamManager{live: map[streamKey]*streamListener{}, tcpIdle: defaultTCPIdle}
}

func (m *streamManager) Sync(hosts []*aegisv1.Host) {
	wanted := map[streamKey]streamSpec{}
	for _, h := range hosts {
		protoName := "tcp"
		if h.GetListenProtocol() == aegisv1.ListenProtocol_LISTEN_PROTOCOL_UDP {
			protoName = "udp"
		}
		if h.GetListenPort() == 0 {
			continue
		}
		addrs := hostUpstreamAddrs(h)
		if len(addrs) == 0 {
			continue
		}
		ups := make([]string, 0, len(addrs))
		for _, a := range addrs {
			ups = append(ups, a.authority())
		}
		k := streamKey{proto: protoName, port: h.GetListenPort()}
		wanted[k] = streamSpec{
			key:       k,
			upstreams: ups,
			acl:       h.GetAccessList(),
			tcpIdle:   m.tcpIdle,
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	for k, ln := range m.live {
		spec, ok := wanted[k]
		if !ok || !ln.spec.equal(spec) {
			ln.cancel()
			delete(m.live, k)
		}
	}
	for k, spec := range wanted {
		if _, ok := m.live[k]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		m.live[k] = &streamListener{cancel: cancel, spec: spec}
		go serveStream(ctx, spec)
	}
}

// Close stops all listeners; Sync will not bring them back.
func (m *streamManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, ln := range m.live {
		ln.cancel()
		delete(m.live, k)
	}
	m.closed = true
}

func serveStream(ctx context.Context, spec streamSpec) {
	addr := ":" + strconv.Itoa(int(spec.key.port))
	if spec.key.proto == "udp" {
		serveUDP(ctx, addr, spec)
		return
	}
	// A listener that cannot bind (port still in TIME_WAIT, another process
	// holding it briefly) or whose Accept fails (file-descriptor exhaustion)
	// is retried, not abandoned: the host stays configured, so the port must
	// come back when the condition clears.
	for ctx.Err() == nil {
		ln, err := listenTCP(ctx, addr)
		if err != nil {
			log.Printf("proxy: stream listen tcp %s: %v; retrying in 5s", addr, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		log.Printf("proxy: stream TCP %s → %s", addr, spec.upstreams[0])
		acceptTCP(ctx, ln, spec)
		if ctx.Err() == nil {
			log.Printf("proxy: stream %s listener lost; re-listening", addr)
		}
	}
}

func acceptTCP(ctx context.Context, ln net.Listener, spec streamSpec) {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	backoff := 5 * time.Millisecond
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// Temporary (EMFILE, ECONNABORTED): pause like net/http does.
			log.Printf("proxy: stream accept %s: %v; retrying in %s", ln.Addr(), err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 5 * time.Millisecond
		if !applyStreamACL(spec.acl, c.RemoteAddr()) {
			c.Close()
			continue
		}
		go proxyTCP(c, spec.upstreams, spec.tcpIdle)
	}
}

func listenTCP(ctx context.Context, addr string) (net.Listener, error) {
	var last error
	for i := 0; i < 40; i++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			return ln, nil
		}
		last = err
		time.Sleep(25 * time.Millisecond)
	}
	return nil, last
}

func proxyTCP(client net.Conn, upstreams []string, idle time.Duration) {
	defer client.Close()
	client = &idleConn{Conn: client, idle: idle}
	var up net.Conn
	var last error
	for i, upstream := range upstreams {
		if i >= upstreamMaxTries {
			break
		}
		c, err := net.DialTimeout("tcp", upstream, 10*time.Second)
		if err != nil {
			last = err
			continue
		}
		up = c
		break
	}
	if up == nil {
		if last != nil {
			log.Printf("proxy: stream dial: %v", last)
		}
		return
	}
	defer up.Close()
	up = &idleConn{Conn: up, idle: idle}
	errc := make(chan struct{}, 2)
	go func() { io.Copy(up, client); errc <- struct{}{} }()
	go func() { io.Copy(client, up); errc <- struct{}{} }()
	<-errc
}

type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	c.refreshIdle()
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	c.refreshIdle()
	return c.Conn.Write(p)
}

func (c *idleConn) refreshIdle() {
	if c.idle > 0 {
		_ = c.Conn.SetDeadline(time.Now().Add(c.idle))
	}
}

func serveUDP(ctx context.Context, addr string, spec streamSpec) {
	pc, err := listenUDP(ctx, addr)
	if err != nil {
		log.Printf("proxy: stream listen udp %s: %v", addr, err)
		return
	}
	log.Printf("proxy: stream UDP %s → %s", addr, spec.upstreams[0])
	go func() {
		<-ctx.Done()
		pc.Close()
	}()

	type sess struct {
		up   net.Conn
		last time.Time
	}
	var mu sync.Mutex
	sessions := map[string]*sess{}
	drop := func(key string, s *sess) {
		if cur, ok := sessions[key]; ok && cur == s {
			delete(sessions, key)
		}
		s.up.Close()
	}
	defer func() {
		mu.Lock()
		for k, s := range sessions {
			s.up.Close()
			delete(sessions, k)
		}
		mu.Unlock()
	}()

	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				mu.Lock()
				for k, s := range sessions {
					if time.Since(s.last) > udpIdle {
						drop(k, s)
					}
				}
				mu.Unlock()
			}
		}
	}()

	buf := make([]byte, 64*1024)
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if !applyStreamACL(spec.acl, raddr) {
			continue
		}
		key := raddr.String()
		mu.Lock()
		s := sessions[key]
		if s == nil {
			if len(sessions) >= udpSessionCap {
				mu.Unlock()
				continue
			}
			up, err := dialUDPFirst(spec.upstreams)
			if err != nil {
				mu.Unlock()
				log.Printf("proxy: stream udp dial: %v", err)
				continue
			}
			s = &sess{up: up, last: time.Now()}
			sessions[key] = s
			go func(key string, s *sess, raddr net.Addr) {
				defer func() {
					mu.Lock()
					drop(key, s)
					mu.Unlock()
				}()
				rbuf := make([]byte, 64*1024)
				for {
					n, err := s.up.Read(rbuf)
					if err != nil {
						return
					}
					mu.Lock()
					s.last = time.Now()
					mu.Unlock()
					_, _ = pc.WriteTo(rbuf[:n], raddr)
				}
			}(key, s, raddr)
		}
		s.last = time.Now()
		up := s.up
		mu.Unlock()
		_, _ = up.Write(buf[:n])
	}
}

func listenUDP(ctx context.Context, addr string) (net.PacketConn, error) {
	var last error
	for i := 0; i < 40; i++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		pc, err := net.ListenPacket("udp", addr)
		if err == nil {
			return pc, nil
		}
		last = err
		time.Sleep(25 * time.Millisecond)
	}
	return nil, last
}

func dialUDPFirst(upstreams []string) (net.Conn, error) {
	var last error
	for i, u := range upstreams {
		if i >= upstreamMaxTries {
			break
		}
		c, err := net.Dial("udp", u)
		if err == nil {
			return c, nil
		}
		last = err
	}
	if last == nil {
		last = errNoUpstream
	}
	return nil, last
}
