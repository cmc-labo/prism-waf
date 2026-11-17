package waf

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cmc-labo/prism-waf/internal/audit"
	"github.com/cmc-labo/prism-waf/internal/grpc"
)

// errCallBlocked ends the request stream of a blocked gRPC call. It is
// context.Canceled, which the transport passes on to the response and the
// proxy does not report as a backend error.
var errCallBlocked = context.Canceled

// serveGRPC inspects a gRPC or gRPC-Web call and forwards it to next.
//
// The method, path and metadata (headers) are checked first. The request
// stream is then inspected message by message while it is forwarded:
// buffering it whole would break streaming calls, in which the client
// waits for responses before it sends more. A message is passed on only
// once it has been inspected. A call in which a message is blocked is
// aborted: if the backend has not answered yet, the client gets a gRPC
// status like any blocked call; otherwise the status ends the response
// that has started.
func serveGRPC(w http.ResponseWriter, r *http.Request, next http.Handler, cfg Config, logger *slog.Logger, protocol grpc.Protocol, codec grpc.Codec) {
	detect := cfg.Mode == ModeDetect
	block := func(code int, eventID string) { blockResponse(w, r, cfg, protocol, code, eventID) }

	violation, md := cfg.GRPC.CheckMethod(r.URL.Path)
	if violation != "" {
		message := "the method is not in the schema"
		if violation == grpc.ViolationReflection {
			message = "server reflection is not allowed"
		}
		id := logAPIEvent(cfg, logger, r, &audit.API{Protocol: "grpc", Violation: violation, Operation: r.URL.Path, Message: message})
		if !detect {
			block(http.StatusForbidden, id)
			return
		}
	}
	if m := cfg.Inspector.InspectHead(r); m != nil {
		id := logEvent(cfg, logger, r, "signature", m)
		if !detect {
			block(http.StatusForbidden, id)
			return
		}
	}
	// The CRS sees the metadata; the messages are binary.
	if cfg.CRS != nil && !inspectCRS(cfg, logger, r, nil, block) {
		return
	}

	var input protoreflect.MessageDescriptor
	if md != nil {
		input = md.Input()
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	r = r.WithContext(ctx)
	call := &grpcCall{}
	r.Body = grpc.NewReader(r.Body, protocol, r.Header.Get("Grpc-Encoding"), int(cfg.Inspector.maxBodySize), func(msg grpc.Message) error {
		code, id := inspectMessage(cfg, logger, r, codec, input, msg)
		if id == "" || detect {
			return nil
		}
		call.status, call.eventID = code, id
		call.blocked.Store(true)
		// Stop the backend's response too.
		cancel()
		return errCallBlocked
	})

	gw := &grpcWriter{ResponseWriter: w, call: call}
	func() {
		defer func() {
			// The proxy aborts a response that it cannot copy to the end,
			// as when the call is blocked after the backend answered.
			if v := recover(); v != nil && (v != http.ErrAbortHandler || !call.blocked.Load()) {
				panic(v)
			}
		}()
		next.ServeHTTP(gw, r)
	}()
	if !call.blocked.Load() {
		return
	}
	message := http.StatusText(call.status) + "; event ID: " + call.eventID
	if !gw.wroteHeader {
		clear(w.Header())
		grpc.WriteError(w, protocol, grpc.StatusFromHTTP(call.status), message)
		return
	}
	grpc.WriteTrailer(w, protocol, grpc.StatusFromHTTP(call.status), message)
}

// inspectMessage inspects a message of a gRPC request stream. It returns
// the HTTP status for a message that must be blocked, and the ID of its
// audit event, or "".
func inspectMessage(cfg Config, logger *slog.Logger, r *http.Request, codec grpc.Codec, input protoreflect.MessageDescriptor, msg grpc.Message) (int, string) {
	switch {
	case msg.Err != nil:
		violation := grpc.ViolationInvalidMessage
		if errors.Is(msg.Err, grpc.ErrUnsupportedEncoding) {
			violation = grpc.ViolationEncoding
		}
		return http.StatusForbidden, logAPIEvent(cfg, logger, r, &audit.API{
			Protocol: "grpc", Violation: violation, Operation: r.URL.Path, Message: msg.Err.Error(),
		})
	case msg.TooLarge:
		return http.StatusRequestEntityTooLarge, logEvent(cfg, logger, r, "body_too_large", nil)
	}

	prefix := "[" + strconv.Itoa(msg.Index) + "]"
	var m *Match
	visit := func(value string, path func() string) error {
		if m = cfg.Inspector.InspectValue(LocationGRPC, "", value); m != nil {
			if p := strings.TrimPrefix(path(), "$"); p != "" && !strings.HasPrefix(p, ".") && !strings.HasPrefix(p, "[") {
				m.Field = prefix + "." + p
			} else {
				m.Field = prefix + p
			}
			return errStopWalk
		}
		return nil
	}
	var err error
	if codec == grpc.JSON {
		if err = walkJSON(msg.Data, visit); err != nil && m == nil {
			// Not JSON: inspected as a whole, like a body.
			m = cfg.Inspector.InspectValue(LocationGRPC, prefix, string(msg.Data))
		}
	} else {
		err = grpc.Walk(msg.Data, input, visit)
	}
	switch {
	case m != nil:
		return http.StatusForbidden, logEvent(cfg, logger, r, "signature", m)
	case errors.Is(err, grpc.ErrInvalidMessage):
		return http.StatusForbidden, logAPIEvent(cfg, logger, r, &audit.API{
			Protocol: "grpc", Violation: grpc.ViolationInvalidMessage, Operation: r.URL.Path,
			Message: "message " + strconv.Itoa(msg.Index) + ": " + err.Error(),
		})
	}
	return 0, ""
}

// grpcCall is the state of a gRPC call, shared between the handler and the
// transport that reads the request stream.
type grpcCall struct {
	// status and eventID are set before blocked.
	status  int
	eventID string
	blocked atomic.Bool
}

// grpcWriter drops the response of a blocked call, so that the handler can
// answer it instead, and tracks whether the response has started.
type grpcWriter struct {
	http.ResponseWriter
	call        *grpcCall
	wroteHeader bool
}

func (w *grpcWriter) WriteHeader(code int) {
	if w.wroteHeader || w.call.blocked.Load() {
		return
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *grpcWriter) Write(b []byte) (int, error) {
	if w.call.blocked.Load() {
		return len(b), nil
	}
	w.wroteHeader = true
	return w.ResponseWriter.Write(b)
}

// Flush sends the messages of a streaming response as they come.
func (w *grpcWriter) Flush() {
	if w.call.blocked.Load() || !w.wroteHeader {
		return
	}
	http.NewResponseController(w.ResponseWriter).Flush()
}

// Unwrap lets http.ResponseController reach the connection.
func (w *grpcWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
