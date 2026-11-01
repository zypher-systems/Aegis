// Package auth implements local admin authentication: argon2id password
// hashing and HMAC-signed session tokens stored in httpOnly cookies.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/zypher-systems/aegis/internal/passwd"
)

// HashPassword returns a PHC-format argon2id hash string.
func HashPassword(password string) (string, error) {
	return passwd.Hash(password)
}

// VerifyPassword constant-time-compares password against a PHC hash.
func VerifyPassword(password, phc string) bool {
	return passwd.Verify(password, phc)
}

// Sessions are HMAC-signed tokens: "userID|expiryUnix|epoch|jti|issuedUnix|sig".
// expiry is the absolute end of the session (ttl after login); issued is when
// this particular token was minted and lets the server enforce an idle
// limit and hand out a refreshed token; jti names the session so logout can
// revoke it server-side; the epoch is users.session_epoch, bumped on
// password change or "sign out everywhere".

// SessionIdle is how long a session may go unused before it ends, whatever
// its absolute expiry. The dashboard renews on activity.
const SessionIdle = 12 * time.Hour

type SessionManager struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

// Session is a parsed, verified token.
type Session struct {
	UserID   string
	Epoch    int
	JTI      string
	IssuedAt time.Time
	Expires  time.Time
}

func NewSessionManager(secret []byte, ttl time.Duration) *SessionManager {
	return &SessionManager{secret: secret, ttl: ttl, now: time.Now}
}

// Issue mints a new session that ends ttl from now.
func (m *SessionManager) Issue(userID string, epoch int) (token string, expires time.Time) {
	expires = m.now().Add(m.ttl)
	return m.mint(Session{UserID: userID, Epoch: epoch, JTI: RandomToken(16), IssuedAt: m.now(), Expires: expires}), expires
}

// Renew re-mints a session with a fresh issue time and the same identity
// and absolute expiry, so activity keeps a session alive up to ttl.
func (m *SessionManager) Renew(s Session) string {
	s.IssuedAt = m.now()
	return m.mint(s)
}

func (m *SessionManager) mint(s Session) string {
	payload := strings.Join([]string{s.UserID, strconv.FormatInt(s.Expires.Unix(), 10), strconv.Itoa(s.Epoch), s.JTI, strconv.FormatInt(s.IssuedAt.Unix(), 10)}, "|")
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + m.sign(payload)))
}

// Parse verifies a token: signature, absolute expiry and idle limit.
func (m *SessionManager) Parse(token string) (Session, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return Session{}, false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 6 {
		return Session{}, false
	}
	payload := strings.Join(parts[:5], "|")
	if !hmac.Equal([]byte(m.sign(payload)), []byte(parts[5])) {
		return Session{}, false
	}
	exp, err1 := strconv.ParseInt(parts[1], 10, 64)
	ep, err2 := strconv.Atoi(parts[2])
	iat, err3 := strconv.ParseInt(parts[4], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || parts[3] == "" {
		return Session{}, false
	}
	now := m.now()
	if now.Unix() > exp || now.Sub(time.Unix(iat, 0)) > SessionIdle {
		return Session{}, false
	}
	return Session{UserID: parts[0], Epoch: ep, JTI: parts[3], IssuedAt: time.Unix(iat, 0), Expires: time.Unix(exp, 0)}, true
}

// Validate is Parse for callers that only need the identity.
func (m *SessionManager) Validate(token string) (userID string, epoch int, ok bool) {
	s, ok := m.Parse(token)
	return s.UserID, s.Epoch, ok
}

// SessionKey derives the cookie-signing key from the master key with
// HKDF-SHA256. The master key also encrypts everything at rest, so it must
// never be used directly for anything that could be compared or leaked.
func SessionKey(master []byte) []byte {
	out := make([]byte, 32)
	r := hkdf.New(sha256.New, master, []byte("aegis-api"), []byte("session-cookie-v1"))
	if _, err := io.ReadFull(r, out); err != nil {
		panic("hkdf: " + err.Error())
	}
	return out
}

func (m *SessionManager) sign(payload string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// RandomToken produces a URL-safe random string for CSRF tokens and similar.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
