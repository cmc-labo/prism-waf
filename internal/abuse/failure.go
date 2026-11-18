package abuse

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/cmc-labo/prism-waf/internal/ratelimit"
)

// DefaultFailureStatuses are the response statuses that count as failures
// if a rule names none: 401 Unauthorized and 403 Forbidden, which login
// endpoints and APIs answer wrong credentials with.
var DefaultFailureStatuses = []StatusRange{{401, 401}, {403, 403}}

// FailureRule allows each client Limit failed requests per Window to the
// requests that Rule matches; more are rejected until the allowance has
// refilled, at the rate of the rate limits.
type FailureRule struct {
	ratelimit.Rule
	// Statuses are the response statuses that count as failures.
	Statuses []StatusRange
}

// StatusRange is a range of HTTP statuses, e.g. 401-401 or 400-499.
type StatusRange struct{ Min, Max int }

func (s StatusRange) String() string {
	switch {
	case s.Min == s.Max:
		return strconv.Itoa(s.Min)
	case s.Min%100 == 0 && s.Max == s.Min+99:
		return strconv.Itoa(s.Min/100) + "xx"
	}
	return strconv.Itoa(s.Min) + "-" + strconv.Itoa(s.Max)
}

// ParseFailureRule parses "[METHOD ]PATH=N/WINDOW[ STATUS,…]", e.g.
// "POST /login=5/15m" or "POST /api/redeem=10/1h 400,404". A status is a
// code such as 401, a class such as 4xx or a range such as 400-409; the
// default is DefaultFailureStatuses.
func ParseFailureRule(s string) (FailureRule, error) {
	i := strings.LastIndex(s, "=")
	if i < 0 {
		return FailureRule{}, fmt.Errorf("abuse: invalid failure rule %q: want [METHOD ]PATH=N/WINDOW[ STATUS,...], e.g. POST /login=5/15m", s)
	}
	rate, statuses, _ := strings.Cut(strings.TrimSpace(s[i+1:]), " ")
	rule, err := ratelimit.ParseRule(s[:i+1] + rate)
	if err != nil {
		return FailureRule{}, fmt.Errorf("abuse: invalid failure rule %q: %w", s, err)
	}
	fr := FailureRule{Rule: rule, Statuses: DefaultFailureStatuses}
	if statuses = strings.TrimSpace(statuses); statuses != "" {
		if fr.Statuses, err = parseStatuses(statuses); err != nil {
			return FailureRule{}, fmt.Errorf("abuse: invalid failure rule %q: %w", s, err)
		}
	}
	return fr, nil
}

func parseStatuses(s string) ([]StatusRange, error) {
	var out []StatusRange
	for _, f := range strings.Split(s, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		var sr StatusRange
		var err1, err2 error
		switch lo, hi, isRange := strings.Cut(f, "-"); {
		case isRange:
			sr.Min, err1 = strconv.Atoi(lo)
			sr.Max, err2 = strconv.Atoi(hi)
		case len(f) == 3 && strings.HasSuffix(f, "xx"):
			sr.Min, err1 = strconv.Atoi(f[:1])
			sr.Min *= 100
			sr.Max = sr.Min + 99
		default:
			sr.Min, err1 = strconv.Atoi(f)
			sr.Max = sr.Min
		}
		if err1 != nil || err2 != nil || sr.Min < 200 || sr.Max > 599 || sr.Min > sr.Max {
			return nil, fmt.Errorf("invalid status %q: want a code from 200 to 599 such as 401, a class such as 4xx or a range such as 400-409", f)
		}
		out = append(out, sr)
	}
	return out, nil
}

// String returns the rule in the syntax of ParseFailureRule, with its
// statuses.
func (r FailureRule) String() string {
	var statuses []string
	for _, s := range r.Statuses {
		statuses = append(statuses, s.String())
	}
	return r.Rule.String() + " " + strings.Join(statuses, ",")
}

// Fails reports whether a response status counts as a failure.
func (r FailureRule) Fails(status int) bool {
	return slices.ContainsFunc(r.Statuses, func(s StatusRange) bool { return s.Min <= status && status <= s.Max })
}
