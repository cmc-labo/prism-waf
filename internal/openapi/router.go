package openapi

import (
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
)

// router finds the operation of a request. Unlike kin-openapi's routers,
// it accepts paths that differ only in the names of their parameters,
// such as GET /items/{id} and DELETE /items/{itemId}, which real
// documents have although OpenAPI forbids them: the path with the
// request's method is used.
type router struct {
	doc *openapi3.T
	// routes by their number of segments, the most specific first.
	routes map[int][]*route
}

type route struct {
	path     string
	item     *openapi3.PathItem
	segments []segment
}

// segment is a segment of a path template: a literal such as "items", or
// a pattern with parameters such as "{id}" or "{name}.{ext}".
type segment struct {
	literal string
	re      *regexp.Regexp
	names   []string
}

// rank orders segments from the most specific: literals, then patterns
// with literal parts, then single parameters.
func (s segment) rank() int {
	switch {
	case s.re == nil:
		return 0
	case len(s.names) == 1 && s.re.String() == "^([^/]+)$":
		return 2
	}
	return 1
}

var parameter = regexp.MustCompile(`\{([^{}]+)\}`)

func newRouter(doc *openapi3.T) *router {
	r := &router{doc: doc, routes: map[int][]*route{}}
	var routes []*route
	for path, item := range doc.Paths.Map() {
		rt := &route{path: path, item: item}
		for _, s := range strings.Split(path, "/")[1:] {
			if !strings.Contains(s, "{") {
				rt.segments = append(rt.segments, segment{literal: s})
				continue
			}
			var seg segment
			expr := "^"
			last := 0
			for _, m := range parameter.FindAllStringSubmatchIndex(s, -1) {
				expr += regexp.QuoteMeta(s[last:m[0]]) + "([^/]+)"
				seg.names = append(seg.names, s[m[2]:m[3]])
				last = m[1]
			}
			seg.re = regexp.MustCompile(expr + regexp.QuoteMeta(s[last:]) + "$")
			rt.segments = append(rt.segments, seg)
		}
		routes = append(routes, rt)
	}
	slices.SortFunc(routes, func(a, b *route) int {
		for i := range min(len(a.segments), len(b.segments)) {
			if d := a.segments[i].rank() - b.segments[i].rank(); d != 0 {
				return d
			}
		}
		return strings.Compare(a.path, b.path)
	})
	for _, rt := range routes {
		r.routes[len(rt.segments)] = append(r.routes[len(rt.segments)], rt)
	}
	return r
}

// match returns the path parameters if the route matches the segments of
// a path.
func (rt *route) match(segs []string) (map[string]string, bool) {
	for i, s := range rt.segments {
		if s.re == nil && s.literal != segs[i] {
			return nil, false
		}
	}
	params := map[string]string{}
	for i, s := range rt.segments {
		if s.re == nil {
			continue
		}
		m := s.re.FindStringSubmatch(segs[i])
		if m == nil {
			return nil, false
		}
		for j, name := range s.names {
			params[name] = m[j+1]
		}
	}
	return params, true
}

// errNoOperation is returned for a CORS preflight request, an OPTIONS
// request to a path without an OPTIONS operation, which is not validated.
var errNoOperation = &routers.RouteError{Reason: "no OPTIONS operation"}

// find returns the operation for the method and path of a request below
// the base path. A trailing slash is ignored. HEAD requests use the GET
// operation if there is no HEAD operation, as backends answer them.
func (r *router) find(method, path string) (*routers.Route, map[string]string, error) {
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	segs := strings.Split(path, "/")[1:]
	found := false
	for _, rt := range r.routes[len(segs)] {
		params, ok := rt.match(segs)
		if !ok {
			continue
		}
		found = true
		op := rt.item.GetOperation(method)
		if op == nil && method == http.MethodHead {
			op = rt.item.GetOperation(http.MethodGet)
		}
		if op != nil {
			return &routers.Route{Spec: r.doc, Path: rt.path, PathItem: rt.item, Method: method, Operation: op}, params, nil
		}
	}
	switch {
	case found && method == http.MethodOptions:
		return nil, nil, errNoOperation
	case found:
		return nil, nil, routers.ErrMethodNotAllowed
	}
	return nil, nil, routers.ErrPathNotFound
}
