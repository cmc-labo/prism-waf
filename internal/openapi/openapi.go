// Package openapi validates requests against an OpenAPI 3.0 or 3.1
// document: requests for operations that the document does not describe,
// and requests whose parameters, body or credentials do not match it, are
// rejected (a positive security model).
package openapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"

	"github.com/cmc-labo/prism-waf/internal/ratelimit"
)

// Violations, the kinds of rejected requests.
const (
	// ViolationUnknownPath is a path that no operation has.
	ViolationUnknownPath = "unknown_path"
	// ViolationMethod is a method that the path has no operation for.
	ViolationMethod    = "method_not_allowed"
	ViolationParameter = "parameter"
	ViolationBody      = "body"
	// ViolationSecurity is a request without the credentials that the
	// operation requires.
	ViolationSecurity = "security"
	ViolationRequest  = "request"
)

// Validator validates requests against an OpenAPI document. It is safe for
// concurrent use.
type Validator struct {
	router *router
	// bases are the base paths of the API, from the document's servers,
	// in lower case and without a trailing slash; "" is the root.
	bases      []string
	operations int
	version    string
}

// Load reads an OpenAPI 3.0 or 3.1 document in YAML or JSON. References
// to other local files are resolved; references to URLs are rejected.
func Load(path string) (*Validator, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(l *openapi3.Loader, u *url.URL) ([]byte, error) {
		if u.Scheme != "" && u.Scheme != "file" {
			return nil, fmt.Errorf("references to URLs are not supported: %s", u)
		}
		return openapi3.ReadFromFile(l, u)
	}
	doc, err := loader.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("openapi: %s: %w", path, err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.") {
		return nil, fmt.Errorf("openapi: %s: version %q is not supported: want OpenAPI 3.0 or 3.1", path, doc.OpenAPI)
	}
	bases, err := basePaths(doc.Servers)
	if err != nil {
		return nil, fmt.Errorf("openapi: %s: %w", path, err)
	}
	// Examples and default values do not take part in validation, and are
	// often wrong in real documents, as are paths that differ only in the
	// names of their parameters, which the router handles.
	err = doc.Validate(loader.Context, openapi3.DisableExamplesValidation(), openapi3.DisableSchemaDefaultsValidation())
	var conflict *openapi3.ConflictingPathsError
	if err != nil && !errors.As(err, &conflict) {
		return nil, fmt.Errorf("openapi: %s: invalid document: %w", path, err)
	}
	router := newRouter(doc)
	v := &Validator{router: router, bases: bases, version: doc.OpenAPI}
	for _, item := range doc.Paths.Map() {
		v.operations += len(item.Operations())
	}
	return v, nil
}

// basePaths returns the paths of the servers' URLs, with their variables
// set to their defaults. Requests outside of them are not validated.
func basePaths(servers openapi3.Servers) ([]string, error) {
	var out []string
	for _, s := range servers {
		raw := s.URL
		for name, v := range s.Variables {
			raw = strings.ReplaceAll(raw, "{"+name+"}", v.Default)
		}
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid server URL %q: %w", s.URL, err)
		}
		p := strings.TrimSuffix(strings.ToLower(u.Path), "/")
		if p != "" {
			p = ratelimit.CleanPath(p)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		out = []string{""}
	}
	// Longest first, so that the most specific base path is used.
	slices.SortFunc(out, func(a, b string) int { return len(b) - len(a) })
	return out, nil
}

// Version returns the OpenAPI version of the document, e.g. "3.1.0".
func (v *Validator) Version() string { return v.version }

// Operations returns the number of operations in the document.
func (v *Validator) Operations() int { return v.operations }

// BasePaths returns the paths that requests are validated under; "/"
// means all requests.
func (v *Validator) BasePaths() []string {
	out := make([]string, len(v.bases))
	for i, b := range v.bases {
		out[i] = b + "/"
	}
	return out
}

// Violation describes a request that does not match the document.
type Violation struct {
	// Kind is one of the Violation constants.
	Kind string
	// Operation is the method and path template of the operation, e.g.
	// "GET /users/{id}", if the request matched one.
	Operation string
	Message   string
}

// Check validates r, whose body has already been read. It returns nil if
// the request matches the document or is outside of its base paths.
func (v *Validator) Check(r *http.Request, body []byte) *Violation {
	rel, ok := v.relativePath(r.URL.Path)
	if !ok {
		return nil
	}
	if rel == "" {
		return &Violation{Kind: ViolationUnknownPath, Message: "the path is not in canonical form"}
	}
	// A shallow copy with the path below the base path and a body that the
	// validator can read.
	vr := r.WithContext(r.Context())
	u := *r.URL
	u.Path, u.RawPath = rel, ""
	vr.URL = &u
	vr.Body = io.NopCloser(bytes.NewReader(body))

	route, params, err := v.router.find(r.Method, rel)
	switch {
	case err == errNoOperation:
		return nil
	case err == routers.ErrMethodNotAllowed:
		return &Violation{Kind: ViolationMethod, Message: r.Method + " is not allowed"}
	case err != nil:
		return &Violation{Kind: ViolationUnknownPath, Message: "no operation matches the path"}
	}
	op := route.Method + " " + route.Path
	// The validator reads the query with url.ParseQuery, which leaves out
	// parameters it cannot parse, such as "a=1;b=2": a backend that splits
	// at semicolons would get parameters that were not validated.
	if _, err := url.ParseQuery(r.URL.RawQuery); err != nil {
		return &Violation{Kind: ViolationParameter, Operation: op, Message: "invalid query string: " + err.Error()}
	}
	err = openapi3filter.ValidateRequest(r.Context(), &openapi3filter.RequestValidationInput{
		Request:    vr,
		PathParams: params,
		Route:      route,
		Options: &openapi3filter.Options{
			AuthenticationFunc: authenticate,
			// The request is only checked; the validator works on a copy.
			SkipSettingDefaults: true,
			// All problems, so that those the validator cannot check can be
			// told from the others.
			MultiError: true,
		},
	})
	for _, err := range flatten(err) {
		if v := violation(err, op); v != nil {
			return v
		}
	}
	return nil
}

// flatten returns the errors of a MultiError.
func flatten(err error) []error {
	me, ok := err.(openapi3.MultiError)
	if !ok {
		if err == nil {
			return nil
		}
		return []error{err}
	}
	var out []error
	for _, e := range me {
		out = append(out, flatten(e)...)
	}
	return out
}

// violation classifies a validation error, or returns nil for parts of
// the document that the validator does not support, which are then not
// validated rather than rejected.
func violation(err error, op string) *Violation {
	var (
		reqErr   *openapi3filter.RequestError
		secErr   *openapi3filter.SecurityRequirementsError
		parseErr *openapi3filter.ParseError
	)
	switch {
	case errors.As(err, &parseErr) && parseErr.Kind == openapi3filter.KindUnsupportedFormat,
		unsupported(err):
		// E.g. a media type that the document allows but the validator
		// cannot decode, such as XML.
		return nil
	case errors.As(err, &secErr):
		return &Violation{Kind: ViolationSecurity, Operation: op, Message: "no credentials for the security requirements of the operation"}
	case errors.As(err, &reqErr) && reqErr.Parameter != nil:
		return &Violation{Kind: ViolationParameter, Operation: op, Message: firstLine(err)}
	case errors.As(err, &reqErr) && reqErr.RequestBody != nil:
		return &Violation{Kind: ViolationBody, Operation: op, Message: firstLine(err)}
	}
	return &Violation{Kind: ViolationRequest, Operation: op, Message: firstLine(err)}
}

// firstLine returns the first line of an error message, without the
// schema and the value that schema errors add.
func firstLine(err error) string {
	s, _, _ := strings.Cut(err.Error(), "\n")
	return strings.TrimSpace(s)
}

// unsupported reports whether err is about a feature that the validator
// does not support, such as arrays in the deepObject style or nested
// objects in a form body, as in Stripe's API.
func unsupported(err error) bool {
	for e := err; e != nil; e = errors.Unwrap(e) {
		s := e.Error()
		if strings.HasPrefix(s, "invalid serialization method") || strings.HasPrefix(s, "unsupported schema of request body") {
			return true
		}
	}
	return false
}

// relativePath returns the path of a request below the longest base path
// that contains it. ok is false for requests outside of the base paths.
// rel is "" if the request is inside a base path only once the path is
// cleaned, e.g. "/api//users" or "/x/../api/users": backends may accept
// such paths, but the document's operations cannot match them.
func (v *Validator) relativePath(p string) (rel string, ok bool) {
	lower := strings.ToLower(p)
	clean := ratelimit.CleanPath(p)
	for _, b := range v.bases {
		if !under(clean, b) {
			continue
		}
		if !under(lower, b) {
			return "", true
		}
		rel = p[len(b):]
		if rel == "" {
			rel = "/"
		}
		return rel, true
	}
	return "", false
}

// under reports whether path p is base or below it.
func under(p, base string) bool {
	return strings.HasPrefix(p, base) && (len(p) == len(base) || p[len(base)] == '/')
}

// authenticate checks that a request has the credentials of a security
// scheme. It cannot check that they are valid, which is the backend's job,
// but it keeps requests without any from reaching it.
func authenticate(_ context.Context, in *openapi3filter.AuthenticationInput) error {
	s := in.SecurityScheme
	r := in.RequestValidationInput.Request
	present := false
	switch s.Type {
	case "apiKey":
		switch s.In {
		case "header":
			present = r.Header.Get(s.Name) != ""
		case "query":
			present = r.URL.Query().Get(s.Name) != ""
		case "cookie":
			c, err := r.Cookie(s.Name)
			present = err == nil && c.Value != ""
		}
	case "http":
		present = hasAuthorization(r, s.Scheme)
	case "oauth2", "openIdConnect":
		present = hasAuthorization(r, "bearer")
	case "mutualTLS":
		present = r.TLS != nil && len(r.TLS.PeerCertificates) > 0
	}
	if !present {
		return fmt.Errorf("no credentials for %q", in.SecuritySchemeName)
	}
	return nil
}

// hasAuthorization reports whether r has an Authorization header with the
// given scheme, e.g. "Bearer abc".
func hasAuthorization(r *http.Request, scheme string) bool {
	s, cred, ok := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	return ok && strings.EqualFold(s, scheme) && strings.TrimSpace(cred) != ""
}
