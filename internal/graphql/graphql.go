// Package graphql protects GraphQL endpoints. It parses the queries of
// GraphQL requests and rejects those that are too expensive to execute
// (too deep, too many fields or aliases, too large batches), that query
// the schema through introspection, or that are not valid for a schema,
// and it extracts the string arguments of queries so that each can be
// inspected on its own.
package graphql

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
	"github.com/vektah/gqlparser/v2/validator"

	"github.com/cmc-labo/prism-waf/internal/ratelimit"
)

// Default limits. They allow the queries of typical applications, whose
// depth is rarely above 10, while stopping queries that make the server
// resolve a huge number of objects.
const (
	DefaultMaxDepth   = 15
	DefaultMaxAliases = 20
	DefaultMaxFields  = 1000
	DefaultMaxBatch   = 10
)

// Violations, the kinds of rejected requests.
const (
	// ViolationInvalid is a request that is not a GraphQL request, or a
	// query that does not parse.
	ViolationInvalid = "invalid"
	// ViolationSchema is a query that is not valid for the schema.
	ViolationSchema        = "schema"
	ViolationDepth         = "depth"
	ViolationAliases       = "aliases"
	ViolationFields        = "fields"
	ViolationBatch         = "batch"
	ViolationIntrospection = "introspection"
)

// Config configures a Guard. Zero limits select the defaults.
type Config struct {
	// Paths are the GraphQL endpoints, e.g. "/graphql", or with a trailing
	// "*" path prefixes, matched like the paths of rate limit rules.
	Paths []string
	// Schema, if set, rejects queries that are not valid for it, e.g. that
	// select fields that do not exist.
	Schema *ast.Schema
	// MaxDepth limits the nesting of fields, e.g. 3 for
	// { user { posts { title } } }.
	MaxDepth int
	// MaxAliases limits the aliased fields per request, which can make
	// the server run one field many times, e.g. to guess passwords.
	MaxAliases int
	// MaxFields limits the fields per request, counting each use of a
	// fragment.
	MaxFields int
	// MaxBatch limits the operations of a batched request (a JSON array).
	MaxBatch int
	// Introspection allows queries of the schema (__schema and __type).
	Introspection bool
}

// Guard checks GraphQL requests. It is safe for concurrent use.
type Guard struct {
	cfg   Config
	paths []string
}

// New returns a Guard.
func New(cfg Config) (*Guard, error) {
	for _, l := range []*int{&cfg.MaxDepth, &cfg.MaxAliases, &cfg.MaxFields, &cfg.MaxBatch} {
		if *l < 0 {
			return nil, errors.New("graphql: limits must not be negative")
		}
	}
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = DefaultMaxDepth
	}
	if cfg.MaxAliases == 0 {
		cfg.MaxAliases = DefaultMaxAliases
	}
	if cfg.MaxFields == 0 {
		cfg.MaxFields = DefaultMaxFields
	}
	if cfg.MaxBatch == 0 {
		cfg.MaxBatch = DefaultMaxBatch
	}
	if len(cfg.Paths) == 0 {
		return nil, errors.New("graphql: no endpoint paths")
	}
	g := &Guard{cfg: cfg}
	for _, p := range cfg.Paths {
		// The parser of rate limit rules, so that both accept and match the
		// same paths.
		r, err := ratelimit.ParseRule(p + "=1/1s")
		if err != nil || r.Method != "" {
			return nil, fmt.Errorf("graphql: invalid path %q: want a path such as /graphql or /api/*", p)
		}
		g.paths = append(g.paths, r.Path)
	}
	return g, nil
}

// Handles reports whether a request path is a GraphQL endpoint.
func (g *Guard) Handles(path string) bool {
	clean := ratelimit.CleanPath(path)
	for _, p := range g.paths {
		if prefix, ok := strings.CutSuffix(p, "*"); ok {
			if strings.HasPrefix(clean, prefix) || clean+"/" == prefix {
				return true
			}
		} else if p == clean {
			return true
		}
	}
	return false
}

// Config returns the configuration of the guard, with defaults applied.
func (g *Guard) Config() Config { return g.cfg }

// LoadSchema reads a schema in the GraphQL schema definition language
// from one or more files.
func LoadSchema(paths []string) (*ast.Schema, error) {
	var sources []*ast.Source
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("graphql: %w", err)
		}
		sources = append(sources, &ast.Source{Name: p, Input: string(b)})
	}
	s, err := gqlparser.LoadSchema(sources...)
	if err != nil {
		return nil, fmt.Errorf("graphql: invalid schema: %w", err)
	}
	return s, nil
}

// Violation describes a rejected request.
type Violation struct {
	// Kind is one of the Violation constants.
	Kind string
	// Operation is the type and name of the operation, e.g.
	// "query GetUser", if the violation is in one.
	Operation string
	// Limit and Value are the exceeded limit and the request's value, for
	// limit violations.
	Limit, Value int
	Message      string
}

// Value is a string argument of a query.
type Value struct {
	// Path locates the value, e.g. "user.posts(filter.title)".
	Path  string
	Value string
}

// request is one GraphQL request of a possibly batched HTTP request.
type request struct {
	Query         *string         `json:"query"`
	OperationName string          `json:"operationName"`
	Extensions    json.RawMessage `json:"extensions"`
}

// Check checks the GraphQL request r, whose body has already been read.
// It returns a violation, or the string arguments of the queries to
// inspect. Requests without a query, such as a GET for an IDE page, pass.
// Queries saved on the server (persisted queries) pass, as their text is
// not in the request.
func (g *Guard) Check(r *http.Request, body []byte) (*Violation, []Value) {
	reqs, err := requests(r, body)
	if err != nil {
		return &Violation{Kind: ViolationInvalid, Message: err.Error()}, nil
	}
	if len(reqs) > g.cfg.MaxBatch {
		return &Violation{Kind: ViolationBatch, Limit: g.cfg.MaxBatch, Value: len(reqs),
			Message: fmt.Sprintf("%d operations in a batch, more than %d", len(reqs), g.cfg.MaxBatch)}, nil
	}
	var total cost
	var values []Value
	for _, q := range reqs {
		if q.Query == nil {
			continue
		}
		doc, err := parser.ParseQuery(&ast.Source{Input: *q.Query})
		if err != nil {
			return &Violation{Kind: ViolationInvalid, Message: err.Error()}, nil
		}
		// Limits come before schema validation, whose cost they bound.
		a := analyzer{doc: doc, fragments: map[string]*cost{}}
		for _, op := range doc.Operations {
			c, err := a.selectionSet(op.SelectionSet)
			if err != nil {
				return &Violation{Kind: ViolationInvalid, Operation: opName(op), Message: err.Error()}, nil
			}
			name := opName(op)
			switch {
			case c.depth > g.cfg.MaxDepth:
				return &Violation{Kind: ViolationDepth, Operation: name, Limit: g.cfg.MaxDepth, Value: c.depth,
					Message: fmt.Sprintf("depth %d, more than %d", c.depth, g.cfg.MaxDepth)}, nil
			case c.introspection != "" && !g.cfg.Introspection:
				return &Violation{Kind: ViolationIntrospection, Operation: name, Message: "introspection field " + c.introspection}, nil
			}
			total.add(c)
			if total.aliases > g.cfg.MaxAliases {
				return &Violation{Kind: ViolationAliases, Operation: name, Limit: g.cfg.MaxAliases, Value: total.aliases,
					Message: fmt.Sprintf("%d aliases, more than %d", total.aliases, g.cfg.MaxAliases)}, nil
			}
			if total.fields > g.cfg.MaxFields {
				return &Violation{Kind: ViolationFields, Operation: name, Limit: g.cfg.MaxFields, Value: total.fields,
					Message: fmt.Sprintf("%d fields, more than %d", total.fields, g.cfg.MaxFields)}, nil
			}
		}
		if g.cfg.Schema != nil {
			if errs := validator.Validate(g.cfg.Schema, doc); len(errs) > 0 {
				return &Violation{Kind: ViolationSchema, Message: errs[0].Message}, nil
			}
		}
		values = append(values, stringValues(doc)...)
	}
	return nil, values
}

// requests extracts the GraphQL requests from an HTTP request: the
// "query" URL parameter of a GET, or the body of a POST as JSON (a request
// or a batch), as application/graphql, as a form or as a multipart file
// upload request.
func requests(r *http.Request, body []byte) ([]request, error) {
	var reqs []request
	// Servers differ in which they use when a POST has both, so both are
	// checked.
	if q := r.URL.Query(); q.Has("query") || q.Has("extensions") {
		reqs = append(reqs, fromValues(q))
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return reqs, nil
	}
	mt, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch mt {
	case "application/graphql":
		q := string(body)
		return append(reqs, request{Query: &q}), nil
	case "application/x-www-form-urlencoded":
		v, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, fmt.Errorf("invalid form: %w", err)
		}
		return append(reqs, fromValues(v)), nil
	case "multipart/form-data":
		// The GraphQL multipart request specification: the operations are
		// in the "operations" field.
		ops, err := multipartField(body, params["boundary"], "operations")
		if err != nil {
			return nil, err
		}
		body = ops
	}
	// JSON, also with other content types, as some servers accept them.
	body = bytes.TrimSpace(body)
	var batch []request
	var err error
	if len(body) > 0 && body[0] == '[' {
		err = json.Unmarshal(body, &batch)
	} else {
		var q request
		err = json.Unmarshal(body, &q)
		batch = []request{q}
	}
	if err != nil {
		return nil, fmt.Errorf("not a GraphQL request: %w", err)
	}
	for _, q := range batch {
		if q.Query == nil && len(q.Extensions) == 0 {
			return nil, errors.New("not a GraphQL request: no query")
		}
	}
	return append(reqs, batch...), nil
}

func fromValues(v url.Values) request {
	q := request{OperationName: v.Get("operationName"), Extensions: json.RawMessage(v.Get("extensions"))}
	if v.Has("query") {
		s := v.Get("query")
		q.Query = &s
	}
	return q
}

func multipartField(body []byte, boundary, name string) ([]byte, error) {
	if boundary == "" {
		return nil, errors.New("invalid multipart request: no boundary")
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			return nil, fmt.Errorf("invalid multipart request: no %q field", name)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid multipart request: %w", err)
		}
		if p.FormName() == name {
			return io.ReadAll(p)
		}
	}
}

func opName(op *ast.OperationDefinition) string {
	s := string(op.Operation)
	if s == "" {
		s = "query"
	}
	if op.Name != "" {
		s += " " + op.Name
	}
	return s
}

// cost is what executing a selection set takes.
type cost struct {
	depth, fields, aliases int
	// introspection is the first introspection field selected.
	introspection string
}

// maxCount caps counts, which grow exponentially with nested fragments.
const maxCount = 1 << 40

func (c *cost) add(o cost) {
	c.depth = max(c.depth, o.depth)
	c.fields = min(c.fields+o.fields, maxCount)
	c.aliases = min(c.aliases+o.aliases, maxCount)
	if c.introspection == "" {
		c.introspection = o.introspection
	}
}

// analyzer computes the cost of the operations of a document, expanding
// fragments. The cost of each fragment is computed once.
type analyzer struct {
	doc       *ast.QueryDocument
	fragments map[string]*cost // nil while being computed, to find cycles
}

func (a *analyzer) selectionSet(set ast.SelectionSet) (cost, error) {
	var c cost
	for _, s := range set {
		switch s := s.(type) {
		case *ast.Field:
			sub, err := a.selectionSet(s.SelectionSet)
			if err != nil {
				return cost{}, err
			}
			f := cost{depth: sub.depth + 1, fields: 1, introspection: sub.introspection}
			if s.Alias != s.Name {
				f.aliases = 1
			}
			if s.Name == "__schema" || s.Name == "__type" {
				f.introspection = s.Name
			}
			f.fields = min(f.fields+sub.fields, maxCount)
			f.aliases = min(f.aliases+sub.aliases, maxCount)
			c.add(f)
		case *ast.InlineFragment:
			sub, err := a.selectionSet(s.SelectionSet)
			if err != nil {
				return cost{}, err
			}
			c.add(sub)
		case *ast.FragmentSpread:
			sub, err := a.fragment(s.Name)
			if err != nil {
				return cost{}, err
			}
			c.add(sub)
		}
	}
	return c, nil
}

func (a *analyzer) fragment(name string) (cost, error) {
	if c, ok := a.fragments[name]; ok {
		if c == nil {
			return cost{}, fmt.Errorf("fragment %q spreads itself", name)
		}
		return *c, nil
	}
	def := a.doc.Fragments.ForName(name)
	if def == nil {
		return cost{}, fmt.Errorf("unknown fragment %q", name)
	}
	a.fragments[name] = nil
	c, err := a.selectionSet(def.SelectionSet)
	if err != nil {
		return cost{}, err
	}
	a.fragments[name] = &c
	return c, nil
}

// stringValues returns the string and enum arguments of fields and
// directives, and the default values of variables, of a document. Each
// literal is returned once, even if its fragment is used several times.
func stringValues(doc *ast.QueryDocument) []Value {
	var out []Value
	// end closes the path of an argument, e.g. "user(filter.name" + ")".
	var value func(path, end string, v *ast.Value)
	value = func(path, end string, v *ast.Value) {
		if v == nil {
			return
		}
		switch v.Kind {
		case ast.StringValue, ast.BlockValue, ast.EnumValue:
			out = append(out, Value{Path: path + end, Value: v.Raw})
		case ast.ListValue:
			for i, c := range v.Children {
				value(path+"["+strconv.Itoa(i)+"]", end, c.Value)
			}
		case ast.ObjectValue:
			for _, c := range v.Children {
				value(path+"."+c.Name, end, c.Value)
			}
		}
	}
	arguments := func(path string, args ast.ArgumentList) {
		for _, arg := range args {
			value(path+"("+arg.Name, ")", arg.Value)
		}
	}
	directives := func(path string, ds ast.DirectiveList) {
		for _, d := range ds {
			arguments(path+"@"+d.Name, d.Arguments)
		}
	}
	var selectionSet func(path string, set ast.SelectionSet)
	selectionSet = func(path string, set ast.SelectionSet) {
		for _, s := range set {
			switch s := s.(type) {
			case *ast.Field:
				p := s.Alias
				if path != "" {
					p = path + "." + p
				}
				arguments(p, s.Arguments)
				directives(p, s.Directives)
				selectionSet(p, s.SelectionSet)
			case *ast.InlineFragment:
				directives(path, s.Directives)
				selectionSet(path, s.SelectionSet)
			case *ast.FragmentSpread:
				directives(path, s.Directives)
			}
		}
	}
	for _, op := range doc.Operations {
		for _, v := range op.VariableDefinitions {
			value("$"+v.Variable, "", v.DefaultValue)
		}
		directives(opName(op), op.Directives)
		selectionSet("", op.SelectionSet)
	}
	for _, f := range doc.Fragments {
		directives("..."+f.Name, f.Directives)
		selectionSet("..."+f.Name, f.SelectionSet)
	}
	return out
}
