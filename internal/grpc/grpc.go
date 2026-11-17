// Package grpc inspects gRPC and gRPC-Web requests. It splits the request
// stream into messages as it is forwarded, so that streaming calls keep
// working, decodes the messages with or without their protobuf schema,
// and answers rejected calls with a gRPC status that clients understand.
package grpc

import (
	"mime"

	"google.golang.org/protobuf/reflect/protoreflect"
	"net/http"
	"strconv"
	"strings"
)

// Protocol is the wire protocol of a request.
type Protocol int

const (
	// None is a request that is not a gRPC call.
	None Protocol = iota
	// GRPC is gRPC over HTTP/2.
	GRPC
	// Web is gRPC-Web, which also works over HTTP/1.1 and returns the
	// trailers in the body.
	Web
	// WebText is gRPC-Web with a Base64-encoded body, for browsers that
	// cannot stream binary data.
	WebText
)

func (p Protocol) String() string {
	switch p {
	case GRPC:
		return "grpc"
	case Web:
		return "grpc-web"
	case WebText:
		return "grpc-web-text"
	}
	return "none"
}

// Codec is the encoding of the messages.
type Codec int

const (
	Proto Codec = iota
	JSON
)

// ProtocolOf returns the protocol and codec of a request from its method
// and Content-Type, e.g. "application/grpc+proto" or
// "application/grpc-web-text". gRPC calls are always POSTs; other
// requests with a gRPC content type are not handled as calls, so that
// the content type cannot exempt them from any check.
func ProtocolOf(r *http.Request) (Protocol, Codec) {
	if r.Method != http.MethodPost {
		return None, Proto
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return None, Proto
	}
	base, sub, _ := strings.Cut(mt, "+")
	var p Protocol
	switch base {
	case "application/grpc":
		p = GRPC
	case "application/grpc-web":
		p = Web
	case "application/grpc-web-text":
		p = WebText
	default:
		return None, Proto
	}
	if sub == "json" {
		return p, JSON
	}
	return p, Proto
}

// Status codes, see https://grpc.github.io/grpc/core/md_doc_statuscodes.html.
const (
	InvalidArgument   = 3
	PermissionDenied  = 7
	ResourceExhausted = 8
	Unimplemented     = 12
	Internal          = 13
	Unavailable       = 14
)

// StatusFromHTTP maps the HTTP status of a rejected request to a gRPC
// status code.
func StatusFromHTTP(code int) int {
	switch code {
	case http.StatusBadRequest:
		return InvalidArgument
	case http.StatusTooManyRequests, http.StatusRequestEntityTooLarge:
		return ResourceExhausted
	case http.StatusNotImplemented, http.StatusNotFound:
		return Unimplemented
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return Unavailable
	case http.StatusForbidden, http.StatusUnauthorized:
		return PermissionDenied
	}
	return Internal
}

// WriteError answers a call that has not started with a gRPC status and
// no messages (a "Trailers-Only" response): HTTP status 200, with the
// status in the headers.
func WriteError(w http.ResponseWriter, p Protocol, code int, message string) {
	h := w.Header()
	switch p {
	case Web:
		h.Set("Content-Type", "application/grpc-web+proto")
	case WebText:
		h.Set("Content-Type", "application/grpc-web-text+proto")
	default:
		h.Set("Content-Type", "application/grpc")
	}
	h.Set("Grpc-Status", strconv.Itoa(code))
	h.Set("Grpc-Message", encodeMessage(message))
	h.Del("Content-Length")
	w.WriteHeader(http.StatusOK)
}

// WriteTrailer ends a call whose response has already started with a
// gRPC status. The handler must return afterwards.
func WriteTrailer(w http.ResponseWriter, p Protocol, code int, message string) {
	if p == GRPC {
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", strconv.Itoa(code))
		w.Header().Set(http.TrailerPrefix+"Grpc-Message", encodeMessage(message))
		return
	}
	// gRPC-Web sends the trailers as the last message, flagged 0x80.
	t := "grpc-status:" + strconv.Itoa(code) + "\r\ngrpc-message:" + encodeMessage(message) + "\r\n"
	frame := append([]byte{trailerFlag, 0, 0, 0, 0}, t...)
	putLength(frame[1:5], len(t))
	if p == WebText {
		frame = []byte(encodeBase64(frame))
	}
	w.Write(frame)
}

// encodeMessage percent-encodes a status message, as gRPC requires for
// bytes outside of printable ASCII and for "%".
func encodeMessage(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '%' {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// IsReflection reports whether path is a method of the server reflection
// service, which lists the services and messages of a server.
func IsReflection(path string) bool {
	return strings.HasPrefix(path, "/grpc.reflection.v1.ServerReflection/") ||
		strings.HasPrefix(path, "/grpc.reflection.v1alpha.ServerReflection/")
}

// IsHealth reports whether path is a method of the standard health
// checking service, which load balancers call.
func IsHealth(path string) bool {
	return strings.HasPrefix(path, "/grpc.health.v1.Health/")
}

// Violations, the kinds of rejected calls.
const (
	// ViolationReflection is a call of the server reflection service.
	ViolationReflection = "reflection"
	// ViolationUnknownMethod is a method that the schema does not have.
	ViolationUnknownMethod = "unknown_method"
	// ViolationInvalidMessage is a message that does not match the type
	// of the method, or a stream that is not made of messages.
	ViolationInvalidMessage = "invalid_message"
	// ViolationEncoding is a compressed message in an encoding that
	// cannot be decompressed for inspection.
	ViolationEncoding = "unsupported_encoding"
)

// Config configures a Guard.
type Config struct {
	// Schema, if set, rejects calls of methods that it does not have, and
	// messages that do not match their type; their strings are then
	// inspected by field name.
	Schema *Schema
	// Reflection allows calls of the server reflection service.
	Reflection bool
}

// Guard checks the methods of gRPC calls.
type Guard struct {
	cfg Config
}

// New returns a Guard.
func New(cfg Config) *Guard { return &Guard{cfg: cfg} }

// Config returns the configuration of the guard.
func (g *Guard) Config() Config { return g.cfg }

// CheckMethod checks the method of a call by its request path. It
// returns the violation, if any, and the method's description from the
// schema, which is nil without a schema and for the methods that are
// allowed without being in it: reflection, if allowed, and health checks.
func (g *Guard) CheckMethod(path string) (violation string, md protoreflect.MethodDescriptor) {
	if IsReflection(path) {
		if !g.cfg.Reflection {
			return ViolationReflection, nil
		}
		return "", nil
	}
	if g.cfg.Schema == nil || IsHealth(path) {
		return "", nil
	}
	if md = g.cfg.Schema.Method(path); md == nil {
		return ViolationUnknownMethod, nil
	}
	return "", md
}
