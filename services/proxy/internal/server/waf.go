package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/internal/clientip"
	"github.com/zypher-systems/aegis/internal/wafrules"
)

const wafProbeID = 19901

type wafResult struct {
	Action  string
	RuleID  string
	Score   float64
	Matches []wafCause
}

type wafResultKey struct{}

func attachWAFResult(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), wafResultKey{}, &wafResult{}))
}

func wafResultFrom(r *http.Request) *wafResult {
	v, _ := r.Context().Value(wafResultKey{}).(*wafResult)
	return v
}

func wafFingerprint(h *aegisv1.Host) string {
	mode := wafrules.NormalizeMode(h.GetWafMode())
	pl := wafrules.NormalizeParanoia(int(h.GetWafParanoia()))
	th := wafrules.NormalizeThreshold(int(h.GetWafInboundThreshold()))
	tags := append([]string(nil), h.GetWafDisabledTags()...)
	var b strings.Builder
	fmt.Fprintf(&b, "%s|%d|%d|%d|%s", mode, pl, th, wafrules.NormalizeBodyLimit(int(h.GetWafBodyLimitBytes())), strings.Join(tags, ","))
	fmt.Fprintf(&b, "|m=%s|ct=%s|any=%t|hd=%s", wafrules.MethodsSecLang(h.GetWafAllowedMethods()),
		wafrules.ContentTypesSecLang(h.GetWafAllowedContentTypes()), h.GetWafAnyContentType(),
		wafrules.RestrictedHeadersSecLang(h.GetWafRestrictedHeaders()))
	for _, e := range h.GetWafExclusions() {
		fmt.Fprintf(&b, "|%s:%s:%s", e.GetRuleId(), e.GetPath(), e.GetTarget())
	}
	return b.String()
}

type wafSlot struct {
	fp  string
	waf coraza.WAF
}

func (s *Server) primeWAF(hosts []*aegisv1.Host) {
	s.wafMu.Lock()
	defer s.wafMu.Unlock()
	nextFP := map[string]coraza.WAF{}
	nextHost := map[string]wafSlot{}
	problems := map[string]wafProblem{}
	for _, h := range hosts {
		if h == nil || !h.GetWafEnabled() {
			continue
		}
		id := h.GetId()
		fp := wafFingerprint(h)
		w, err := s.lookupOrCompileWAFLocked(fp, h, nextFP)
		if err != nil || w == nil {
			if old, ok := s.wafByHost[id]; ok && old.waf != nil {
				log.Printf("proxy: waf compile %s: %v; keeping last-good", fp, err)
				nextHost[id] = old
				nextFP[old.fp] = old.waf
				problems[id] = wafProblem{resource: firstDomain(h), detail: "The current WAF profile failed to compile; this node is still running the previous rules. " + compileErr(err)}
			} else {
				log.Printf("proxy: waf compile %s: %v; fail-open (no last-good)", fp, err)
				problems[id] = wafProblem{resource: firstDomain(h), detail: "The WAF profile failed to compile and there are no previous rules, so the WAF is off for this host. " + compileErr(err)}
			}
			continue
		}
		nextFP[fp] = w
		if id != "" {
			nextHost[id] = wafSlot{fp: fp, waf: w}
		}
	}
	s.wafCache = nextFP
	s.wafByHost = nextHost
	s.wafProblems = problems
}

func compileErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return "Error: " + msg
}

func (s *Server) lookupOrCompileWAFLocked(fp string, h *aegisv1.Host, nextFP map[string]coraza.WAF) (coraza.WAF, error) {
	if w, ok := nextFP[fp]; ok {
		return w, nil
	}
	if w, ok := s.wafCache[fp]; ok {
		return w, nil
	}
	return compileWAF(h)
}

func (s *Server) wafFor(h *aegisv1.Host) coraza.WAF {
	if h == nil || !h.GetWafEnabled() {
		return nil
	}
	fp := wafFingerprint(h)
	s.wafMu.Lock()
	defer s.wafMu.Unlock()
	if id := h.GetId(); id != "" {
		if slot, ok := s.wafByHost[id]; ok {
			return slot.waf
		}
	}
	if w, ok := s.wafCache[fp]; ok {
		return w
	}
	w, err := compileWAF(h)
	if err != nil {
		log.Printf("proxy: waf compile %s: %v; fail-open", fp, err)
		return nil
	}
	if s.wafCache == nil {
		s.wafCache = map[string]coraza.WAF{}
	}
	s.wafCache[fp] = w
	if id := h.GetId(); id != "" {
		if s.wafByHost == nil {
			s.wafByHost = map[string]wafSlot{}
		}
		s.wafByHost[id] = wafSlot{fp: fp, waf: w}
	}
	return w
}

func compileWAF(h *aegisv1.Host) (coraza.WAF, error) {
	mode := wafrules.NormalizeMode(h.GetWafMode())
	pl := wafrules.NormalizeParanoia(int(h.GetWafParanoia()))
	th := wafrules.NormalizeThreshold(int(h.GetWafInboundThreshold()))
	bodyLimit := wafrules.NormalizeBodyLimit(int(h.GetWafBodyLimitBytes()))
	engine := "On"
	if mode == "detect" {
		engine = "DetectionOnly"
	}

	var dirs []string
	dirs = append(dirs,
		"Include @coraza.conf-recommended",
		"Include @crs-setup.conf.example",
		fmt.Sprintf(`SecAction "id:19001,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=%d"`, pl),
		fmt.Sprintf(`SecAction "id:19002,phase:1,nolog,pass,t:none,setvar:tx.detection_paranoia_level=%d"`, pl),
		fmt.Sprintf(`SecAction "id:19003,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=%d"`, th),
		// Protocol policy, set before CRS so its initialization rules keep
		// these instead of the form-app defaults (see wafrules/policy.go).
		fmt.Sprintf(`SecAction "id:19004,phase:1,nolog,pass,t:none,setvar:'tx.allowed_methods=%s'"`, wafrules.MethodsSecLang(h.GetWafAllowedMethods())),
		fmt.Sprintf(`SecAction "id:19005,phase:1,nolog,pass,t:none,setvar:'tx.allowed_request_content_type=%s'"`, wafrules.ContentTypesSecLang(h.GetWafAllowedContentTypes())),
		fmt.Sprintf(`SecAction "id:19006,phase:1,nolog,pass,t:none,setvar:'tx.restricted_headers_basic=%s'"`, wafrules.RestrictedHeadersSecLang(h.GetWafRestrictedHeaders())),
		"Include @owasp_crs/*.conf",
	)
	if h.GetWafAnyContentType() {
		dirs = append(dirs, "SecRuleRemoveById 920420")
	}
	for _, tag := range wafrules.NormalizeDisabledTags(h.GetWafDisabledTags()) {
		dirs = append(dirs, "SecRuleRemoveByTag "+tag)
	}
	exclID := 19910
	for _, e := range h.GetWafExclusions() {
		rid := strings.TrimSpace(e.GetRuleId())
		if rid == "" {
			continue
		}
		if unsafeWAFToken(rid) {
			return nil, fmt.Errorf("waf exclusion rule id %q is not a token", rid)
		}
		path := e.GetPath()
		target := wafrules.NormalizeTarget(e.GetTarget())
		// Checked again here: the value is written into a SecLang directive.
		if err := wafrules.ValidateTarget(target); err != nil {
			return nil, err
		}
		if path != "" && unsafeWAFToken(path) {
			return nil, fmt.Errorf("waf exclusion path %q is not a token", path)
		}
		switch {
		case path == "" && target == "":
			dirs = append(dirs, "SecRuleRemoveById "+rid)
		case path == "":
			// The rule keeps inspecting everything except this input.
			dirs = append(dirs, fmt.Sprintf(`SecRuleUpdateTargetById %s "!%s"`, rid, target))
		case target == "":
			dirs = append(dirs, fmt.Sprintf(
				`SecRule REQUEST_FILENAME "@beginsWith %s" "id:%d,phase:1,pass,nolog,ctl:ruleRemoveById=%s"`,
				path, exclID, rid,
			))
			exclID++
		default:
			dirs = append(dirs, fmt.Sprintf(
				`SecRule REQUEST_FILENAME "@beginsWith %s" "id:%d,phase:1,pass,nolog,ctl:ruleRemoveTargetById=%s;%s"`,
				path, exclID, rid, target,
			))
			exclID++
		}
	}
	dirs = append(dirs,
		fmt.Sprintf(`SecRule REQUEST_FILENAME "@streq /waf-probe" "id:%d,phase:1,deny,status:403,log,msg:'aegis probe'"`, wafProbeID),
		// Inspect the first bodyLimit bytes and forward the rest, instead of
		// the recommended-config default of rejecting the request (which
		// turned every upload over the limit into a 413).
		fmt.Sprintf("SecRequestBodyLimit %d", bodyLimit),
		fmt.Sprintf("SecRequestBodyInMemoryLimit %d", bodyLimit),
		"SecRequestBodyLimitAction ProcessPartial",
		"SecRuleEngine "+engine,
	)

	cfg := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithRequestBodyAccess().
		WithRequestBodyLimit(bodyLimit).
		WithRequestBodyInMemoryLimit(bodyLimit)
	for _, d := range dirs {
		cfg = cfg.WithDirectives(d)
	}
	return coraza.NewWAF(cfg)
}

func unsafeWAFToken(s string) bool {
	return strings.ContainsAny(s, "\"'\n\r;")
}

func (s *Server) wafWrap(h *aegisv1.Host) func(http.Handler) http.Handler {
	waf := s.wafFor(h)
	return func(next http.Handler) http.Handler {
		if waf == nil {
			return next
		}
		threshold := wafrules.NormalizeThreshold(int(h.GetWafInboundThreshold()))
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tx := waf.NewTransaction()
			defer func() {
				tx.ProcessLogging()
				_ = tx.Close()
			}()

			ip, port := connectionAddr(r, s.trustedCIDRs())
			tx.ProcessConnection(ip, port, "", 80)
			uri := "/"
			if r.URL != nil {
				if s := r.URL.RequestURI(); s != "" {
					uri = s
				}
			}
			tx.ProcessURI(uri, r.Method, r.Proto)
			if r.URL != nil {
				for k, vs := range r.URL.Query() {
					for _, v := range vs {
						tx.AddGetRequestArgument(k, v)
					}
				}
			}
			for name, values := range r.Header {
				for _, v := range values {
					tx.AddRequestHeader(name, v)
				}
			}
			if r.Host != "" {
				tx.AddRequestHeader("Host", r.Host)
				tx.SetServerName(r.Host)
			}
			for _, te := range r.TransferEncoding {
				tx.AddRequestHeader("Transfer-Encoding", te)
			}

			if it := tx.ProcessRequestHeaders(); it != nil {
				recordWAFHit(r, tx, it)
				writeWAFInterrupt(w, r, it, threshold)
				return
			}
			if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
				it, _, err := tx.ReadRequestBodyFrom(r.Body)
				if err != nil {
					log.Printf("proxy: waf body: %v", err)
				}
				if it != nil {
					recordWAFHit(r, tx, it)
					writeWAFInterrupt(w, r, it, threshold)
					return
				}
				rbr, err := tx.RequestBodyReader()
				if err != nil {
					rbr = bytes.NewReader(nil)
				}
				r.Body = io.NopCloser(io.MultiReader(rbr, r.Body))
			}
			if it, err := tx.ProcessRequestBody(); err == nil && it != nil {
				recordWAFHit(r, tx, it)
				writeWAFInterrupt(w, r, it, threshold)
				return
			}
			if wafrules.NormalizeMode(h.GetWafMode()) == "detect" {
				recordWAFHit(r, tx, nil)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeWAFInterrupt(w http.ResponseWriter, r *http.Request, it *types.Interruption, threshold int) {
	detail := "rule " + strconv.Itoa(it.RuleID) + " denied the request"
	if hit := wafResultFrom(r); hit != nil && hit.Score > 0 {
		detail = fmt.Sprintf("inbound anomaly score %g reached the threshold of %d", hit.Score, threshold)
	}
	setBlock(r, stageWAF, detail)
	status := it.Status
	if status < 400 {
		status = http.StatusForbidden
	}
	writeError(w, r, status)
}

func recordWAFHit(r *http.Request, tx types.Transaction, it *types.Interruption) {
	hit := wafResultFrom(r)
	if hit == nil {
		return
	}
	causes := contributingRules(tx)
	if it != nil {
		hit.Action = "block"
		if it.RuleID != 0 {
			hit.RuleID = strconv.Itoa(it.RuleID)
		}
	} else if len(causes) > 0 {
		// Detect mode: flag only when a detection rule matched. CRS's own
		// bookkeeping (paranoia-level skips such as 980014, setup rules)
		// "matches" every request and says nothing about it.
		hit.Action = "detect"
	}
	// 949110 only says "the anomaly score went over the threshold". Report the
	// highest-scoring rule that got it there, which is what an operator can
	// act on (fix the request, or add an exclusion for that rule).
	if len(causes) > 0 && (hit.RuleID == "949110" || hit.RuleID == "") {
		hit.RuleID = causes[0].id
	}
	hit.Score = inboundScore(tx)
	if hit.Action == "" {
		return
	}
	hit.Matches = causes
	if len(causes) > 0 {
		parts := make([]string, 0, len(causes))
		for _, c := range causes {
			part := c.id + " " + strconv.Quote(c.msg)
			if w := c.where(); w != "" {
				part += " at " + w
			}
			parts = append(parts, part)
		}
		path := ""
		if r.URL != nil {
			path = r.URL.Path
		}
		log.Printf("proxy: waf %s host=%s path=%s score=%g rules: %s", hit.Action, r.Host, path, hit.Score, strings.Join(parts, "; "))
	}
}

type wafCause struct {
	id       string
	msg      string
	sev      int    // lower is more severe (CRS: 2 critical … 5 notice)
	variable string // REQUEST_COOKIES
	key      string // session
	value    string // the matched input, truncated to wafValueMax
}

// wafValueMax bounds a matched value kept for telemetry; the log line
// shortens it further.
const wafValueMax = 256

// where is the log form: ARGS:filter="{\"$ne\":1}" (value truncated).
func (c wafCause) where() string {
	w := c.variable
	if c.key != "" {
		w += ":" + c.key
	}
	if v := c.value; v != "" {
		const max = 60
		if len(v) > max {
			v = v[:max] + "…"
		}
		w += "=" + strconv.Quote(v)
	}
	return w
}

// contributingRules lists the CRS detection rules that matched, most severe
// first, leaving out CRS's own bookkeeping (anomaly evaluation 949xxx,
// 959xxx, 980xxx and the setup rules below 911000).
func contributingRules(tx types.Transaction) []wafCause {
	if tx == nil {
		return nil
	}
	seen := map[int]bool{}
	var out []wafCause
	for _, m := range tx.MatchedRules() {
		id := m.Rule().ID()
		if id < 911000 || id >= 949000 || seen[id] || m.Message() == "" {
			continue
		}
		seen[id] = true
		c := wafCause{id: strconv.Itoa(id), msg: m.Message(), sev: int(m.Rule().Severity())}
		if md := m.MatchedDatas(); len(md) > 0 {
			d := md[0]
			c.variable = d.Variable().Name()
			c.key = d.Key()
			c.value = truncateUTF8(d.Value(), wafValueMax)
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].sev < out[j].sev })
	return out
}

func inboundScore(tx types.Transaction) float64 {
	if tx == nil {
		return 0
	}
	var best float64
	for _, m := range tx.MatchedRules() {
		if n := parseScore(m.Data()); n > best {
			best = n
		}
		if n := parseScore(m.Message()); n > best {
			best = n
		}
		for _, d := range m.MatchedDatas() {
			k := strings.ToLower(d.Key())
			if !strings.Contains(k, "anomaly_score") {
				continue
			}
			n, err := strconv.ParseFloat(d.Value(), 64)
			if err == nil && n > best {
				best = n
			}
		}
	}
	return best
}

func parseScore(s string) float64 {
	const mark = "Total Score: "
	i := strings.Index(s, mark)
	if i < 0 {
		return 0
	}
	rest := s[i+len(mark):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.ParseFloat(rest[:end], 64)
	if err != nil {
		return 0
	}
	return n
}

func connectionAddr(r *http.Request, trusted []string) (string, int) {
	ip := clientip.FromRequest(r, trusted)
	if ip == "" {
		ip = "127.0.0.1"
	}
	port := 0
	if r != nil && r.RemoteAddr != "" {
		if _, p, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			port, _ = strconv.Atoi(p)
		}
	}
	return ip, port
}

// truncateUTF8 cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
