// Package crs runs the OWASP Core Rule Set (CRS) v4 with the Coraza WAF
// engine.
//
// The rules are embedded in the binary (github.com/corazawaf/coraza-coreruleset)
// and run in anomaly scoring mode: each matching rule adds to the request's
// anomaly score, and the request is an attack when the score reaches the
// inbound threshold. Only request rules are loaded; responses are not
// inspected.
package crs

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// Version is the version of the embedded CRS.
const Version = "4.25.0"

// Default settings. The paranoia level and threshold are CRS's defaults;
// the argument limit is Coraza's.
const (
	DefaultParanoiaLevel    = 1
	DefaultInboundThreshold = 5
	DefaultMaxArgs          = 1000
)

// TooManyArgsRuleID is the rule that rejects requests with more than
// Config.MaxArgs arguments.
const TooManyArgsRuleID = 9500001

// Config configures New.
type Config struct {
	// ParanoiaLevel (1-4) selects how many rules are active. Higher levels
	// detect more attacks but cause more false positives. Zero means
	// DefaultParanoiaLevel.
	ParanoiaLevel int
	// InboundThreshold is the anomaly score at which a request is an attack.
	// A critical rule scores 5. Zero means DefaultInboundThreshold.
	InboundThreshold int
	// RulesBefore are SecLang files loaded after the CRS setup but before
	// the CRS rules, e.g. rule exclusions using ctl:ruleRemoveById or
	// settings that override tx variables.
	RulesBefore []string
	// RulesAfter are SecLang files loaded after the CRS rules, e.g. rule
	// exclusions using SecRuleRemoveById or SecRuleUpdateTargetById.
	RulesAfter []string
	// MaxArgs is the largest number of arguments (query and body
	// parameters, JSON and XML values) a request may have. Requests with
	// more are rejected with 400 Bad Request regardless of their anomaly
	// score: Coraza does not inspect arguments beyond its limit, so they
	// could hide a payload, and each argument costs about 0.1 ms. Zero
	// means DefaultMaxArgs.
	MaxArgs int
	// MaxBodySize is the request body size limit, which the caller has
	// already enforced. Zero means 128 KiB.
	MaxBodySize int64
}

// Engine inspects requests with the CRS. It is safe for concurrent use.
type Engine struct {
	waf coraza.WAF
}

// New loads the CRS.
func New(cfg Config) (*Engine, error) {
	if cfg.ParanoiaLevel == 0 {
		cfg.ParanoiaLevel = DefaultParanoiaLevel
	}
	if cfg.ParanoiaLevel < 1 || cfg.ParanoiaLevel > 4 {
		return nil, fmt.Errorf("crs: paranoia level %d must be between 1 and 4", cfg.ParanoiaLevel)
	}
	if cfg.InboundThreshold == 0 {
		cfg.InboundThreshold = DefaultInboundThreshold
	}
	if cfg.InboundThreshold < 1 {
		return nil, fmt.Errorf("crs: inbound anomaly score threshold %d must be positive", cfg.InboundThreshold)
	}
	if cfg.MaxArgs == 0 {
		cfg.MaxArgs = DefaultMaxArgs
	}
	if cfg.MaxArgs < 1 {
		return nil, fmt.Errorf("crs: argument limit %d must be positive", cfg.MaxArgs)
	}
	if cfg.MaxBodySize <= 0 {
		cfg.MaxBodySize = 128 << 10
	}
	directives, err := buildDirectives(cfg)
	if err != nil {
		return nil, err
	}
	w, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(directives).
		WithRequestBodyLimit(int(cfg.MaxBodySize)).
		WithRequestBodyInMemoryLimit(int(cfg.MaxBodySize)))
	if err != nil {
		return nil, fmt.Errorf("crs: loading rules: %w", err)
	}
	return &Engine{waf: w}, nil
}

func buildDirectives(cfg Config) (string, error) {
	var b strings.Builder
	// Coraza's recommended settings, mainly the JSON and XML body
	// processors, then overrides for running as an inline request filter.
	b.WriteString("Include @coraza.conf-recommended\n")
	b.WriteString("SecRuleEngine On\n")
	b.WriteString("SecRequestBodyAccess On\n")
	b.WriteString("SecResponseBodyAccess Off\n")
	b.WriteString("SecAuditEngine Off\n")
	b.WriteString("Include @crs-setup.conf.example\n")
	fmt.Fprintf(&b, `SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"`+"\n", cfg.ParanoiaLevel)
	fmt.Fprintf(&b, `SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d"`+"\n", cfg.InboundThreshold)
	// Coraza stops adding arguments at SecArgumentsLimit and the rules never
	// see the rest, so a payload placed after enough dummy arguments would
	// pass. Keep one more than allowed and reject such requests outright,
	// before the expensive attack rules run.
	fmt.Fprintf(&b, "SecArgumentsLimit %d\n", cfg.MaxArgs+1)
	fmt.Fprintf(&b, `SecRule &ARGS "@gt %d" "id:%d,phase:2,deny,status:400,log,t:none,severity:CRITICAL,msg:'Too many arguments in request (limit %d)',tag:'attack-protocol',tag:'PrismWAF'"`+"\n",
		cfg.MaxArgs, TooManyArgsRuleID, cfg.MaxArgs)
	if err := includeFiles(&b, cfg.RulesBefore); err != nil {
		return "", err
	}
	b.WriteString("Include @owasp_crs/REQUEST-*.conf\n")
	if err := includeFiles(&b, cfg.RulesAfter); err != nil {
		return "", err
	}
	return b.String(), nil
}

// includeFiles adds the contents of local rule files. They are inlined
// rather than included because the rules' root file system is the
// embedded CRS. Glob patterns are expanded.
func includeFiles(b *strings.Builder, patterns []string) error {
	for _, p := range patterns {
		files, err := filepath.Glob(p)
		if err != nil {
			return fmt.Errorf("crs: invalid rule file pattern %q: %w", p, err)
		}
		if len(files) == 0 {
			return fmt.Errorf("crs: no rule files match %q", p)
		}
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				return fmt.Errorf("crs: reading rule file: %w", err)
			}
			// Includes would resolve against the embedded CRS.
			if includeDirective.Match(data) {
				return fmt.Errorf("crs: %s: Include is not supported in rule files; list each file instead", f)
			}
			fmt.Fprintf(b, "# %s\n%s\n", f, data)
		}
	}
	return nil
}

var includeDirective = regexp.MustCompile(`(?m)^\s*Include\s`)

// RuleMatch is a CRS rule that matched a request.
type RuleMatch struct {
	ID      int
	Message string
	Data    string
	// Severity is "critical", "error", "warning" or "notice" for rules that
	// add to the anomaly score (5, 4, 3 and 2 points), and empty for the
	// deciding rule.
	Severity string
	Tags     []string
	// Variable is where the rule matched, e.g. "ARGS:q" or
	// "REQUEST_HEADERS:User-Agent".
	Variable string
	// Value is the matched value.
	Value string
}

// Result is the outcome of inspecting a request.
type Result struct {
	// RuleID is the rule that decided the request is an attack: usually
	// 949110 (anomaly score exceeded), or a rule that rejects the request
	// on its own, such as 200002 (request body could not be parsed).
	RuleID int
	// Status is the HTTP status the rule asks for, e.g. 403 or 400.
	Status int
	// AnomalyScore is the inbound anomaly score, if the decision was based
	// on it, and 0 otherwise.
	AnomalyScore int
	// Matches are the rules that matched, in evaluation order: the rules
	// that add to the anomaly score, and the deciding rule. Informational
	// rules without a severity are left out.
	Matches []RuleMatch
}

// Inspect checks r, whose body is passed separately as it has already
// been read; body is nil if it is not available. clientIP is the client
// address as determined by the caller, and id is used as the transaction
// ID. It returns nil if the request is not an attack.
func (e *Engine) Inspect(r *http.Request, body []byte, clientIP, id string) (*Result, error) {
	tx := e.waf.NewTransactionWithID(id)
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	cport := 0
	if _, p, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		cport, _ = strconv.Atoi(p)
	}
	server, sport := "", 0
	if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if h, p, err := net.SplitHostPort(addr.String()); err == nil {
			server = h
			sport, _ = strconv.Atoi(p)
		}
	}
	tx.ProcessConnection(clientIP, cport, server, sport)
	tx.ProcessURI(r.RequestURI, r.Method, r.Proto)
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	// net/http moves these out of the header map.
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}
	if r.ContentLength > 0 && r.Header.Get("Content-Length") == "" {
		tx.AddRequestHeader("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}

	it := tx.ProcessRequestHeaders()
	if it == nil && tx.IsRequestBodyAccessible() && len(body) > 0 {
		var err error
		if it, _, err = tx.WriteRequestBody(body); err != nil {
			return nil, fmt.Errorf("crs: writing request body: %w", err)
		}
	}
	if it == nil {
		var err error
		if it, err = tx.ProcessRequestBody(); err != nil {
			return nil, fmt.Errorf("crs: processing request body: %w", err)
		}
	}
	if it == nil {
		return nil, nil
	}
	return newResult(it, tx.MatchedRules()), nil
}

var totalScore = regexp.MustCompile(`Total Score: (\d+)`)

func newResult(it *types.Interruption, matched []types.MatchedRule) *Result {
	res := &Result{RuleID: it.RuleID, Status: it.Status}
	if res.Status == 0 {
		res.Status = http.StatusForbidden
	}
	for _, mr := range matched {
		meta := mr.Rule()
		if mr.Message() == "" || meta.Severity() == types.RuleSeverityUnset && meta.ID() != it.RuleID {
			continue
		}
		m := RuleMatch{
			ID:       meta.ID(),
			Message:  mr.Message(),
			Data:     mr.Data(),
			Severity: severity(meta.Severity()),
			Tags:     meta.Tags(),
		}
		if md := mr.MatchedDatas(); len(md) > 0 {
			m.Variable = md[0].Variable().Name()
			if k := md[0].Key(); k != "" {
				m.Variable += ":" + k
			}
			m.Value = md[0].Value()
		}
		if m.ID == it.RuleID {
			if s := totalScore.FindStringSubmatch(m.Message); s != nil {
				res.AnomalyScore, _ = strconv.Atoi(s[1])
			}
		}
		res.Matches = append(res.Matches, m)
	}
	return res
}

// Attack returns the main finding to report. If the deciding rule rejects
// requests on its own, such as 200002 (unparsable body), it is that rule.
// Otherwise, when the anomaly score decided, it is the most severe of the
// rules that added to the score, the first one if several are equally
// severe.
func (r *Result) Attack() *RuleMatch {
	best := -1
	for i, m := range r.Matches {
		if m.ID == r.RuleID {
			if m.Severity != "" {
				return &r.Matches[i]
			}
			continue
		}
		if best < 0 || severityRank[m.Severity] > severityRank[r.Matches[best].Severity] {
			best = i
		}
	}
	if best < 0 {
		for i, m := range r.Matches {
			if m.ID == r.RuleID {
				return &r.Matches[i]
			}
		}
		return nil
	}
	return &r.Matches[best]
}

// severity returns the name of s, or "" if the rule has no severity, like
// the deciding rule.
func severity(s types.RuleSeverity) string {
	if s == types.RuleSeverityUnset {
		return ""
	}
	return s.String()
}

var severityRank = map[string]int{
	"notice": 1, "warning": 2, "error": 3, "critical": 4, "alert": 5, "emergency": 6,
}
