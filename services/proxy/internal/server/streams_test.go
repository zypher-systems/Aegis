package server

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func TestStreamTCPEcho(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	_, upPort, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	listen := ln.Addr().(*net.TCPAddr).Port + 1
	// Find a free listen port.
	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen = l2.Addr().(*net.TCPAddr).Port
	l2.Close()

	s := New()
	s.Apply(&aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "s", DomainNames: []string{"echo"}, Enabled: true,
			Kind:           aegisv1.HostKind_HOST_KIND_STREAM,
			ListenProtocol: aegisv1.ListenProtocol_LISTEN_PROTOCOL_TCP,
			ListenPort:     uint32(listen),
			UpstreamHost:   "127.0.0.1",
			UpstreamPort:   uint32(mustAtoi(upPort)),
		}},
	})
	t.Cleanup(func() { s.Apply(&aegisv1.ConfigUpdate{Version: 2}) })

	deadline := time.Now().Add(2 * time.Second)
	var c net.Conn
	for time.Now().Before(deadline) {
		c, err = net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(listen)), 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if c == nil {
		t.Fatalf("dial stream: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q", buf)
	}
}

func TestTCPStreamIdleTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c)
	}()
	_, upPort, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	listen := freePort(t)
	s := New()
	s.streams.tcpIdle = 80 * time.Millisecond
	s.Apply(&aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "idle", DomainNames: []string{"idle"}, Enabled: true,
			Kind:           aegisv1.HostKind_HOST_KIND_STREAM,
			ListenProtocol: aegisv1.ListenProtocol_LISTEN_PROTOCOL_TCP,
			ListenPort:     uint32(listen),
			UpstreamHost:   "127.0.0.1",
			UpstreamPort:   uint32(mustAtoi(upPort)),
		}},
	})
	t.Cleanup(func() { s.Apply(&aegisv1.ConfigUpdate{Version: 2}) })

	var c net.Conn
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err = net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(listen)), 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if c == nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	time.Sleep(200 * time.Millisecond)
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = c.Read(buf)
	if err == nil {
		t.Fatal("idle TCP session should have closed")
	}
}

func TestStreamUpstreamReload(t *testing.T) {
	echoA := udpOrTCPEcho(t, "tcp", []byte("aaa"))
	echoB := udpOrTCPEcho(t, "tcp", []byte("bbb"))
	listen := freePort(t)

	s := New()
	applyStream := func(ver uint64, upPort int) {
		s.Apply(&aegisv1.ConfigUpdate{
			Version: ver,
			Hosts: []*aegisv1.Host{{
				Id: "s", DomainNames: []string{"echo"}, Enabled: true,
				Kind:           aegisv1.HostKind_HOST_KIND_STREAM,
				ListenProtocol: aegisv1.ListenProtocol_LISTEN_PROTOCOL_TCP,
				ListenPort:     uint32(listen),
				UpstreamHost:   "127.0.0.1",
				UpstreamPort:   uint32(upPort),
			}},
		})
	}
	applyStream(1, echoA)
	t.Cleanup(func() { s.Apply(&aegisv1.ConfigUpdate{Version: 9}) })
	deadline := time.Now().Add(2 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		got = dialTCPExpect(t, listen, "x")
		if got == "aaa" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got != "aaa" {
		t.Fatalf("before reload got %q", got)
	}
	applyStream(2, echoB)
	deadline = time.Now().Add(2 * time.Second)
	got = ""
	for time.Now().Before(deadline) {
		got = dialTCPExpect(t, listen, "x")
		if got == "bbb" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("after reload got %q want bbb", got)
}

func TestStreamUDPEcho(t *testing.T) {
	up := startUDPEcho(t)
	listen := freeUDPPort(t)
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "u", DomainNames: []string{"echo"}, Enabled: true,
			Kind:           aegisv1.HostKind_HOST_KIND_STREAM,
			ListenProtocol: aegisv1.ListenProtocol_LISTEN_PROTOCOL_UDP,
			ListenPort:     uint32(listen),
			UpstreamHost:   "127.0.0.1",
			UpstreamPort:   uint32(up),
		}},
	})
	t.Cleanup(func() { s.Apply(&aegisv1.ConfigUpdate{Version: 2}) })

	deadline := time.Now().Add(2 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(listen)))
		if err != nil {
			last = err
			time.Sleep(20 * time.Millisecond)
			continue
		}
		c.SetDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := c.Write([]byte("ping")); err != nil {
			last = err
			c.Close()
			time.Sleep(20 * time.Millisecond)
			continue
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			last = err
			c.Close()
			time.Sleep(20 * time.Millisecond)
			continue
		}
		c.Close()
		if string(buf) != "ping" {
			t.Fatalf("got %q", buf)
		}
		return
	}
	t.Fatalf("udp echo: %v", last)
}

func udpOrTCPEcho(t *testing.T, network string, reply []byte) int {
	t.Helper()
	ln, err := net.Listen(network, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 16)
				_, _ = c.Read(buf)
				_, _ = c.Write(reply)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func startUDPEcho(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	return p
}

func dialTCPExpect(t *testing.T, listen int, payload string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(listen)), 500*time.Millisecond)
	if err != nil {
		return ""
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte(payload)); err != nil {
		return ""
	}
	buf := make([]byte, 8)
	n, err := c.Read(buf)
	if err != nil {
		return ""
	}
	return string(buf[:n])
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
