package server

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The access log rotates itself by size: access.log → access.log.1 … .N,
// then the oldest is deleted, so it can never grow past roughly
// (accessLogKeep+1) × accessLogMaxBytes. CrowdSec's file acquisition
// follows the name across the rename.
const (
	accessLogMaxBytes = 100 << 20
	accessLogKeep     = 3
)

type accessLog struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
	// rotation policy; tests lower them
	maxBytes int64
	keep     int
}

func newAccessLog(path string) *accessLog {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil
	}
	l := &accessLog{path: path, f: f, maxBytes: accessLogMaxBytes, keep: accessLogKeep}
	if st, err := f.Stat(); err == nil {
		l.size = st.Size()
	}
	return l
}

// rotateLocked shifts the numbered copies up, renames the live file to .1
// and reopens a fresh one. On any error it keeps writing to the old file.
func (l *accessLog) rotateLocked() {
	for i := l.keep - 1; i >= 1; i-- {
		_ = os.Rename(l.numbered(i), l.numbered(i+1))
	}
	if err := os.Rename(l.path, l.numbered(1)); err != nil {
		return
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		// The rename happened; reopening failed. Keep the old handle so
		// lines are not lost, and try again on the next write.
		_ = os.Rename(l.numbered(1), l.path)
		return
	}
	_ = l.f.Close()
	l.f = f
	l.size = 0
	_ = os.Remove(l.numbered(l.keep + 1))
}

func (l *accessLog) numbered(i int) string { return l.path + "." + strconv.Itoa(i) }

func (l *accessLog) Write(r *http.Request, status, bytes int, trusted []string) {
	if l == nil || l.f == nil || r == nil {
		return
	}
	ip := clientIPString(r, trusted)
	if ip == "" {
		ip = "-"
	}
	path := "/"
	if r.URL != nil && r.URL.RequestURI() != "" {
		path = r.URL.RequestURI()
	}
	req := fmt.Sprintf("%s %s HTTP/1.1", r.Method, path)
	ua := r.UserAgent()
	if ua == "" {
		ua = "-"
	}
	ref := r.Referer()
	if ref == "" {
		ref = "-"
	}
	line := fmt.Sprintf("%s - - [%s] %q %d %d %q %q\n",
		ip,
		time.Now().UTC().Format("02/Jan/2006:15:04:05 -0700"),
		req,
		status,
		bytes,
		escapeLog(ref),
		escapeLog(ua),
	)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.size+int64(len(line)) > l.maxBytes && l.size > 0 {
		l.rotateLocked()
	}
	n, _ := l.f.WriteString(line)
	l.size += int64(n)
}

func escapeLog(s string) string {
	if s == "" {
		return "-"
	}
	return strings.ReplaceAll(s, `"`, `'`)
}
