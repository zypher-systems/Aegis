package wafrules

import (
	"bufio"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
)

// Rule is one CRS detection rule as the dashboard names it.
type Rule struct {
	ID       string `json:"id"`
	Message  string `json:"message"`
	Severity string `json:"severity,omitempty"` // CRITICAL, ERROR, WARNING, NOTICE
	Paranoia int    `json:"paranoia,omitempty"`
	Category string `json:"category"` // "SQL injection", "Protocol enforcement", …
	File     string `json:"-"`
}

var (
	rulesOnce sync.Once
	rulesList []Rule
	rulesByID map[string]Rule
)

// Rules is the CRS catalog (rules that carry a message), sorted by id.
func Rules() []Rule {
	rulesOnce.Do(loadRules)
	return rulesList
}

// RuleByID looks one rule up.
func RuleByID(id string) (Rule, bool) {
	rulesOnce.Do(loadRules)
	r, ok := rulesByID[id]
	return r, ok
}

// RuleName is the rule's message, or "" for an unknown id.
func RuleName(id string) string {
	r, _ := RuleByID(id)
	return r.Message
}

var (
	ruleIDRe   = regexp.MustCompile(`\bid:'?(\d+)'?`)
	ruleMsgRe  = regexp.MustCompile(`\bmsg:'((?:[^'\\]|\\.)*)'`)
	ruleSevRe  = regexp.MustCompile(`\bseverity:'([A-Z]+)'`)
	rulePLRe   = regexp.MustCompile(`tag:'paranoia-level/(\d)'`)
	fileCatRe  = regexp.MustCompile(`^(?:REQUEST|RESPONSE)-(\d+)-(.+)\.conf$`)
	categories = map[string]string{
		"911": "Method enforcement", "913": "Scanner detection", "920": "Protocol enforcement",
		"921": "Protocol attack", "922": "Multipart attack", "930": "Path traversal (LFI)",
		"931": "Remote file inclusion", "932": "Command injection (RCE)", "933": "PHP injection",
		"934": "Generic attack", "941": "Cross-site scripting", "942": "SQL injection",
		"943": "Session fixation", "944": "Java attack", "949": "Blocking evaluation",
		"950": "Data leakage", "951": "SQL data leakage", "952": "Java data leakage",
		"953": "PHP data leakage", "954": "IIS data leakage", "955": "Web shells", "956": "Ruby data leakage",
	}
)

func loadRules() {
	rulesByID = map[string]Rule{}
	entries, err := fs.ReadDir(coreruleset.FS, "@owasp_crs")
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		m := fileCatRe.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		category := categories[m[1]]
		if category == "" {
			category = strings.ReplaceAll(strings.Title(strings.ToLower(m[2])), "-", " ")
		}
		f, err := coreruleset.FS.Open("@owasp_crs/" + name)
		if err != nil {
			continue
		}
		parseRules(f, category, name)
		f.Close()
	}
	// Coraza's recommended configuration adds a few rules of its own.
	for id, msg := range map[string]string{
		"200002": "Failed to parse request body",
		"200003": "Multipart request body failed strict validation",
		"200004": "Multipart parser detected a possible unmatched boundary",
		"200005": "ModSecurity internal error flagged",
	} {
		rulesByID[id] = Rule{ID: id, Message: msg, Severity: "CRITICAL", Category: "Request parsing (Coraza)"}
	}
	for _, r := range rulesByID {
		rulesList = append(rulesList, r)
	}
	sort.Slice(rulesList, func(i, j int) bool { return rulesList[i].ID < rulesList[j].ID })
}

// parseRules joins SecLang continuation lines into one directive each and
// keeps the rules that name themselves with msg:.
func parseRules(f fs.File, category, file string) {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var cur strings.Builder
	flush := func() {
		d := cur.String()
		cur.Reset()
		if !strings.HasPrefix(d, "SecRule") && !strings.HasPrefix(d, "SecAction") {
			return
		}
		id := ruleIDRe.FindStringSubmatch(d)
		msg := ruleMsgRe.FindStringSubmatch(d)
		if id == nil || msg == nil {
			return
		}
		n, _ := strconv.Atoi(id[1])
		if n < 911000 || (n >= 949000 && n < 950000) || n >= 959000 {
			return // setup and bookkeeping rules
		}
		r := Rule{ID: id[1], Message: strings.ReplaceAll(msg[1], `\'`, "'"), Category: category, File: file}
		if s := ruleSevRe.FindStringSubmatch(d); s != nil {
			r.Severity = s[1]
		}
		if p := rulePLRe.FindStringSubmatch(d); p != nil {
			r.Paranoia, _ = strconv.Atoi(p[1])
		}
		if _, dup := rulesByID[r.ID]; !dup {
			rulesByID[r.ID] = r
		}
	}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, `\`) {
			cur.WriteString(strings.TrimSuffix(line, `\`))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(line)
		flush()
	}
	flush()
}
