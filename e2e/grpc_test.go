//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	reflectionpb "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// searchProto is the service of the gRPC tests:
//
//	package test;
//	message Filter { string name = 1; }
//	message SearchRequest { string query = 1; Filter filter = 2; repeated string tags = 3; int64 limit = 4; }
//	message SearchReply { string text = 1; }
//	service Search {
//	  rpc Find(SearchRequest) returns (SearchReply);                 // unary
//	  rpc List(SearchRequest) returns (stream SearchReply);          // server streaming
//	  rpc Collect(stream SearchRequest) returns (SearchReply);       // client streaming
//	  rpc Chat(stream SearchRequest) returns (stream SearchReply);   // bidirectional
//	}
var searchProto = &descriptorpb.FileDescriptorProto{
	Name:    proto.String("test/search.proto"),
	Package: proto.String("test"),
	Syntax:  proto.String("proto3"),
	MessageType: []*descriptorpb.DescriptorProto{
		{Name: proto.String("Filter"), Field: []*descriptorpb.FieldDescriptorProto{
			field("name", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
		}},
		{Name: proto.String("SearchRequest"), Field: []*descriptorpb.FieldDescriptorProto{
			field("query", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
			field("filter", 2, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, ".test.Filter"),
			repeated(field("tags", 3, descriptorpb.FieldDescriptorProto_TYPE_STRING, "")),
			field("limit", 4, descriptorpb.FieldDescriptorProto_TYPE_INT64, ""),
		}},
		{Name: proto.String("SearchReply"), Field: []*descriptorpb.FieldDescriptorProto{
			field("text", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
		}},
	},
	Service: []*descriptorpb.ServiceDescriptorProto{{
		Name: proto.String("Search"),
		Method: []*descriptorpb.MethodDescriptorProto{
			method("Find", false, false),
			method("List", false, true),
			method("Collect", true, false),
			method("Chat", true, true),
		},
	}},
}

func field(name string, num int32, typ descriptorpb.FieldDescriptorProto_Type, typeName string) *descriptorpb.FieldDescriptorProto {
	f := &descriptorpb.FieldDescriptorProto{
		Name: proto.String(name), JsonName: proto.String(name), Number: proto.Int32(num), Type: typ.Enum(),
		Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
	}
	if typeName != "" {
		f.TypeName = proto.String(typeName)
	}
	return f
}

func repeated(f *descriptorpb.FieldDescriptorProto) *descriptorpb.FieldDescriptorProto {
	f.Label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	return f
}

func method(name string, clientStreams, serverStreams bool) *descriptorpb.MethodDescriptorProto {
	return &descriptorpb.MethodDescriptorProto{
		Name: proto.String(name), InputType: proto.String(".test.SearchRequest"), OutputType: proto.String(".test.SearchReply"),
		ClientStreaming: proto.Bool(clientStreams), ServerStreaming: proto.Bool(serverStreams),
	}
}

var (
	searchFile                       protoreflect.FileDescriptor
	searchRequestType, searchReplyMD protoreflect.MessageDescriptor
)

func init() {
	fd, err := protodesc.NewFile(searchProto, nil)
	if err != nil {
		panic(err)
	}
	searchFile = fd
	searchRequestType = fd.Messages().ByName("SearchRequest")
	searchReplyMD = fd.Messages().ByName("SearchReply")
}

// writeDescriptorSet writes the descriptor set of the test service, as
// protoc --descriptor_set_out would.
func writeDescriptorSet(t *testing.T) string {
	t.Helper()
	b, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{searchProto}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "search.binpb")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// searchRequest is a SearchRequest.
type searchRequest struct {
	query, filter string
	tags          []string
	limit         int64
}

func (s searchRequest) message() *dynamicpb.Message {
	m := dynamicpb.NewMessage(searchRequestType)
	fields := searchRequestType.Fields()
	if s.query != "" {
		m.Set(fields.ByName("query"), protoreflect.ValueOfString(s.query))
	}
	if s.filter != "" {
		f := dynamicpb.NewMessage(fields.ByName("filter").Message())
		f.Set(f.Descriptor().Fields().ByName("name"), protoreflect.ValueOfString(s.filter))
		m.Set(fields.ByName("filter"), protoreflect.ValueOfMessage(f))
	}
	if len(s.tags) > 0 {
		l := m.Mutable(fields.ByName("tags")).List()
		for _, tag := range s.tags {
			l.Append(protoreflect.ValueOfString(tag))
		}
	}
	if s.limit != 0 {
		m.Set(fields.ByName("limit"), protoreflect.ValueOfInt64(s.limit))
	}
	return m
}

func reply(text string) *dynamicpb.Message {
	m := dynamicpb.NewMessage(searchReplyMD)
	m.Set(searchReplyMD.Fields().ByName("text"), protoreflect.ValueOfString(text))
	return m
}

func replyText(m *dynamicpb.Message) string {
	return m.Get(searchReplyMD.Fields().ByName("text")).String()
}

func queryOf(m *dynamicpb.Message) string {
	return m.Get(searchRequestType.Fields().ByName("query")).String()
}

// grpcBackend is a gRPC server with the Search service, the health service
// and server reflection. It records the queries it receives.
type grpcBackend struct {
	URL string
	mu  sync.Mutex
	got []string
	md  []metadata.MD
}

func (b *grpcBackend) record(ctx context.Context, m *dynamicpb.Message) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.got = append(b.got, queryOf(m))
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		b.md = append(b.md, md)
	}
}

// received returns the queries the backend received.
func (b *grpcBackend) received() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.got)
}

func startGRPCBackend(t *testing.T, opts ...grpc.ServerOption) *grpcBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &grpcBackend{URL: "http://" + ln.Addr().String()}
	srv := grpc.NewServer(opts...)
	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "test.Search",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "Find",
			Handler: func(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				m := dynamicpb.NewMessage(searchRequestType)
				if err := dec(m); err != nil {
					return nil, err
				}
				b.record(ctx, m)
				return reply("found " + queryOf(m)), nil
			},
		}},
		Streams: []grpc.StreamDesc{
			{StreamName: "List", ServerStreams: true, Handler: func(_ any, s grpc.ServerStream) error {
				m := dynamicpb.NewMessage(searchRequestType)
				if err := s.RecvMsg(m); err != nil {
					return err
				}
				b.record(s.Context(), m)
				for i := range 3 {
					if err := s.SendMsg(reply(queryOf(m) + " " + string(rune('1'+i)))); err != nil {
						return err
					}
				}
				return nil
			}},
			{StreamName: "Collect", ClientStreams: true, Handler: func(_ any, s grpc.ServerStream) error {
				var all []string
				for {
					m := dynamicpb.NewMessage(searchRequestType)
					err := s.RecvMsg(m)
					if err == io.EOF {
						return s.SendMsg(reply(strings.Join(all, ",")))
					}
					if err != nil {
						return err
					}
					b.record(s.Context(), m)
					all = append(all, queryOf(m))
				}
			}},
			{StreamName: "Chat", ClientStreams: true, ServerStreams: true, Handler: func(_ any, s grpc.ServerStream) error {
				// Answers each message at once: the client waits for the
				// answer before it sends the next message.
				for {
					m := dynamicpb.NewMessage(searchRequestType)
					err := s.RecvMsg(m)
					if err == io.EOF {
						return nil
					}
					if err != nil {
						return err
					}
					b.record(s.Context(), m)
					if err := s.SendMsg(reply("echo " + queryOf(m))); err != nil {
						return err
					}
				}
			}},
		},
	}, nil)
	healthpb.RegisterHealthServer(srv, health.NewServer())
	reflection.Register(srv)
	go srv.Serve(ln)
	t.Cleanup(srv.Stop)
	return b
}

// startGRPCWAF starts prismwaf in front of a new gRPC backend.
func startGRPCWAF(t *testing.T, o wafOptions, opts ...grpc.ServerOption) (*waf, *grpcBackend) {
	t.Helper()
	b := startGRPCBackend(t, opts...)
	o.backend = b.URL
	return startWAF(t, o), b
}

// dial connects a gRPC client to prismwaf, over h2c or TLS.
func (w *waf) dial(t *testing.T, opts ...grpc.DialOption) *grpc.ClientConn {
	t.Helper()
	target := strings.TrimPrefix(strings.TrimPrefix(w.URL, "http://"), "https://")
	creds := insecure.NewCredentials()
	if strings.HasPrefix(w.URL, "https://") {
		creds = credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})
	}
	conn, err := grpc.NewClient(target, append([]grpc.DialOption{grpc.WithTransportCredentials(creds)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func grpcContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func find(t *testing.T, conn *grpc.ClientConn, req searchRequest, opts ...grpc.CallOption) (string, error) {
	t.Helper()
	out := dynamicpb.NewMessage(searchReplyMD)
	err := conn.Invoke(grpcContext(t), "/test.Search/Find", req.message(), out, opts...)
	return replyText(out), err
}

// grpcEventRe finds the event ID in the status message of a blocked call.
var grpcEventRe = regexp.MustCompile(`event ID: ([0-9a-f]{16})`)

// checkGRPCBlock checks that a call was blocked with the status code and
// returns its audit event.
func checkGRPCBlock(t *testing.T, w *waf, err error, code codes.Code) auditEvent {
	t.Helper()
	s, _ := status.FromError(err)
	m := grpcEventRe.FindStringSubmatch(s.Message())
	if s.Code() != code || m == nil {
		t.Fatalf("status %v %q, want %v with an event ID", s.Code(), s.Message(), code)
	}
	return w.eventByID(t, m[1])
}

// TestGRPCUnary sends unary calls through prismwaf over h2c, which needs
// HTTP/2 on both sides: clean calls pass with their metadata, and an
// attack in any string field, also nested or repeated, is blocked with
// PermissionDenied before it reaches the backend.
func TestGRPCUnary(t *testing.T) {
	w, b := startGRPCWAF(t, wafOptions{})
	conn := w.dial(t)

	ctx := metadata.AppendToOutgoingContext(grpcContext(t), "x-tenant", "acme")
	out := dynamicpb.NewMessage(searchReplyMD)
	if err := conn.Invoke(ctx, "/test.Search/Find", searchRequest{query: "running shoes", filter: "size 42", tags: []string{"sale"}, limit: 5}.message(), out); err != nil {
		t.Fatalf("clean call: %v\n%s", err, w.stderr)
	}
	if replyText(out) != "found running shoes" {
		t.Errorf("reply %q", replyText(out))
	}
	if md := b.md[0]; md.Get("x-tenant")[0] != "acme" {
		t.Errorf("backend metadata %v", md)
	}

	for _, tc := range []struct {
		name  string
		req   searchRequest
		field string
		value string
	}{
		{"field", searchRequest{query: "' OR 1=1--"}, "[0].1", "' OR 1=1--"},
		{"nested", searchRequest{query: "shoes", filter: "<script>alert(1)</script>"}, "[0].2.1", "<script>alert(1)</script>"},
		{"repeated", searchRequest{query: "shoes", tags: []string{"sale", "../../../etc/passwd"}}, "[0].3", "../../../etc/passwd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := find(t, conn, tc.req)
			e := checkGRPCBlock(t, w, err, codes.PermissionDenied)
			if e.Reason != "signature" || e.Action != "block" || e.Match == nil || e.Match.Location != "grpc" ||
				e.Match.Field != tc.field || e.Match.Value != tc.value || e.Request.URI != "/test.Search/Find" {
				t.Errorf("event %+v, match %+v", e, e.Match)
			}
		})
	}
	if got := b.received(); !slices.Equal(got, []string{"running shoes"}) {
		t.Errorf("backend received %q", got)
	}

	// Metadata is inspected like headers.
	ctx = metadata.AppendToOutgoingContext(grpcContext(t), "x-tenant", "1 UNION SELECT password FROM users")
	err := conn.Invoke(ctx, "/test.Search/Find", searchRequest{query: "shoes"}.message(), dynamicpb.NewMessage(searchReplyMD))
	if e := checkGRPCBlock(t, w, err, codes.PermissionDenied); e.Match == nil || e.Match.Location != "header" || e.Match.Field != "X-Tenant" {
		t.Errorf("metadata event %+v", e.Match)
	}
}

// TestGRPCStreaming checks that streaming calls keep streaming through
// prismwaf, which inspects each message on its own: in a bidirectional
// stream, the client waits for each answer before it sends the next
// message, which would hang if prismwaf waited for the whole request. A
// message with an attack ends the call with PermissionDenied, also after
// the backend has started to answer, and never reaches the backend.
func TestGRPCStreaming(t *testing.T) {
	w, b := startGRPCWAF(t, wafOptions{})
	conn := w.dial(t)

	t.Run("server", func(t *testing.T) {
		s, err := conn.NewStream(grpcContext(t), &grpc.StreamDesc{ServerStreams: true}, "/test.Search/List")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SendMsg(searchRequest{query: "page"}.message()); err != nil {
			t.Fatal(err)
		}
		s.CloseSend()
		var got []string
		for {
			m := dynamicpb.NewMessage(searchReplyMD)
			if err := s.RecvMsg(m); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			got = append(got, replyText(m))
		}
		if !slices.Equal(got, []string{"page 1", "page 2", "page 3"}) {
			t.Errorf("replies %q", got)
		}
	})

	t.Run("bidi", func(t *testing.T) {
		s, err := conn.NewStream(grpcContext(t), &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, "/test.Search/Chat")
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{"hello", "how are you"} {
			if err := s.SendMsg(searchRequest{query: q}.message()); err != nil {
				t.Fatal(err)
			}
			m := dynamicpb.NewMessage(searchReplyMD)
			if err := s.RecvMsg(m); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
			if replyText(m) != "echo "+q {
				t.Errorf("reply %q", replyText(m))
			}
		}
		// The response has started: the status comes in the trailers.
		s.SendMsg(searchRequest{query: "1; DROP TABLE users--"}.message())
		err = s.RecvMsg(dynamicpb.NewMessage(searchReplyMD))
		e := checkGRPCBlock(t, w, err, codes.PermissionDenied)
		if e.Match == nil || e.Match.Field != "[2].1" || e.Request.URI != "/test.Search/Chat" {
			t.Errorf("event %+v", e.Match)
		}
	})

	t.Run("client", func(t *testing.T) {
		s, err := conn.NewStream(grpcContext(t), &grpc.StreamDesc{ClientStreams: true}, "/test.Search/Collect")
		if err != nil {
			t.Fatal(err)
		}
		s.SendMsg(searchRequest{query: "a"}.message())
		s.SendMsg(searchRequest{query: "b"}.message())
		s.SendMsg(searchRequest{query: "<img src=x onerror=alert(1)>"}.message())
		s.CloseSend()
		err = s.RecvMsg(dynamicpb.NewMessage(searchReplyMD))
		if e := checkGRPCBlock(t, w, err, codes.PermissionDenied); e.Match == nil || e.Match.Field != "[2].1" {
			t.Errorf("event %+v", e.Match)
		}
	})

	// "a" and "b" may not reach the backend either, if they came with the
	// attack in one read.
	if got := slices.DeleteFunc(b.received(), func(q string) bool { return q == "a" || q == "b" }); !slices.Equal(got, []string{"page", "hello", "how are you"}) {
		t.Errorf("backend received %q", got)
	}
	if strings.Contains(w.stderr.String(), "ReverseProxy") {
		t.Errorf("blocked calls are logged as proxy errors:\n%s", w.stderr)
	}
	if strings.Contains(w.stderr.String(), "backend request failed") {
		t.Errorf("blocked calls are logged as backend errors:\n%s", w.stderr)
	}
}

// TestGRPCDescriptor validates calls against the descriptor set of the
// service: other methods are rejected, messages must match the method's
// input type, and matches name the field. Health checks always pass.
func TestGRPCDescriptor(t *testing.T) {
	w, b := startGRPCWAF(t, wafOptions{args: []string{"-grpc-descriptor", writeDescriptorSet(t)}})
	w.waitLog(t, `msg="gRPC schema validation enabled"`, "services=[test.Search]")
	conn := w.dial(t)

	if out, err := find(t, conn, searchRequest{query: "shoes", filter: "red", tags: []string{"x"}, limit: 3}); err != nil || out != "found shoes" {
		t.Fatalf("clean call: %q %v", out, err)
	}
	_, err := find(t, conn, searchRequest{query: "shoes", filter: "1' AND SLEEP(5)#"})
	if e := checkGRPCBlock(t, w, err, codes.PermissionDenied); e.Match == nil || e.Match.Field != "[0].filter.name" {
		t.Errorf("event %+v", e.Match)
	}
	_, err = find(t, conn, searchRequest{query: "shoes", tags: []string{"ok", "<script>"}})
	if e := checkGRPCBlock(t, w, err, codes.PermissionDenied); e.Match == nil || e.Match.Field != "[0].tags[1]" {
		t.Errorf("event %+v", e.Match)
	}

	// A method that is not in the schema.
	err = conn.Invoke(grpcContext(t), "/test.Search/Delete", searchRequest{query: "all"}.message(), dynamicpb.NewMessage(searchReplyMD))
	e := checkGRPCBlock(t, w, err, codes.PermissionDenied)
	if e.Reason != "api" || e.API == nil || e.API.Protocol != "grpc" || e.API.Violation != "unknown_method" || e.API.Operation != "/test.Search/Delete" {
		t.Errorf("event %+v, api %+v", e, e.API)
	}

	// A message that does not match the input type: "limit" as a string.
	bad := dynamicpb.NewMessage(searchReplyMD) // field 1 is a string in both
	raw, _ := proto.Marshal(bad)
	raw = append(raw, 0x22, 3, 'a', 'b', 'c') // field 4 (int64) with wire type 2
	err = conn.Invoke(grpcContext(t), "/test.Search/Find", rawMessage(raw), dynamicpb.NewMessage(searchReplyMD), grpc.ForceCodecV2(rawCodec{}))
	e = checkGRPCBlock(t, w, err, codes.PermissionDenied)
	if e.API == nil || e.API.Violation != "invalid_message" || !strings.Contains(e.API.Message, "message 0") {
		t.Errorf("api %+v", e.API)
	}

	// Health checks, which load balancers call, are not in the schema.
	res, err := healthpb.NewHealthClient(conn).Check(grpcContext(t), &healthpb.HealthCheckRequest{})
	if err != nil || res.Status != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("health check: %v %v", res, err)
	}
	if got := b.received(); !slices.Equal(got, []string{"shoes"}) {
		t.Errorf("backend received %q", got)
	}
}

// TestGRPCReflection blocks the server reflection service, which lists
// the services and messages of a server, unless -grpc-reflection allows
// it.
func TestGRPCReflection(t *testing.T) {
	listServices := func(conn *grpc.ClientConn) ([]string, error) {
		s, err := reflectionpb.NewServerReflectionClient(conn).ServerReflectionInfo(grpcContext(t))
		if err != nil {
			return nil, err
		}
		if err := s.Send(&reflectionpb.ServerReflectionRequest{MessageRequest: &reflectionpb.ServerReflectionRequest_ListServices{}}); err != nil {
			return nil, err
		}
		res, err := s.Recv()
		if err != nil {
			return nil, err
		}
		var names []string
		for _, svc := range res.GetListServicesResponse().GetService() {
			names = append(names, svc.Name)
		}
		return names, nil
	}

	w, _ := startGRPCWAF(t, wafOptions{})
	_, err := listServices(w.dial(t))
	e := checkGRPCBlock(t, w, err, codes.PermissionDenied)
	if e.API == nil || e.API.Violation != "reflection" || e.API.Operation != "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo" {
		t.Errorf("api %+v", e.API)
	}

	w, _ = startGRPCWAF(t, wafOptions{args: []string{"-grpc-reflection"}})
	names, err := listServices(w.dial(t))
	if err != nil || !slices.Contains(names, "test.Search") {
		t.Errorf("services %q, %v", names, err)
	}
}

// TestGRPCCompression inspects gzip-compressed messages, and blocks
// messages that prismwaf cannot decompress or that decompress to more
// than -max-body.
func TestGRPCCompression(t *testing.T) {
	w, b := startGRPCWAF(t, wafOptions{args: []string{"-max-body", "4096"}})
	conn := w.dial(t)
	gz := grpc.UseCompressor(gzip.Name)

	if out, err := find(t, conn, searchRequest{query: "compressed"}, gz); err != nil || out != "found compressed" {
		t.Fatalf("clean call: %q %v", out, err)
	}
	_, err := find(t, conn, searchRequest{query: "admin' OR '1'='1"}, gz)
	if e := checkGRPCBlock(t, w, err, codes.PermissionDenied); e.Match == nil || e.Match.Field != "[0].1" {
		t.Errorf("event %+v", e.Match)
	}
	// 100 KB of spaces compress to about 130 bytes.
	_, err = find(t, conn, searchRequest{query: strings.Repeat(" ", 100_000)}, gz)
	if e := checkGRPCBlock(t, w, err, codes.ResourceExhausted); e.Reason != "body_too_large" {
		t.Errorf("event %+v", e)
	}
	_, err = find(t, conn, searchRequest{query: strings.Repeat("x", 5000)})
	if e := checkGRPCBlock(t, w, err, codes.ResourceExhausted); e.Reason != "body_too_large" {
		t.Errorf("event %+v", e)
	}
	if got := b.received(); !slices.Equal(got, []string{"compressed"}) {
		t.Errorf("backend received %d queries", len(got))
	}
}

// TestGRPCModes covers detection mode, where attacks reach the backend
// and are only logged, and the other protections, whose rejections are
// gRPC statuses: rate limits (ResourceExhausted) and bot protection,
// whose challenge a gRPC client cannot run (PermissionDenied).
func TestGRPCModes(t *testing.T) {
	t.Run("detect", func(t *testing.T) {
		w, b := startGRPCWAF(t, wafOptions{args: []string{"-mode", "detect"}})
		conn := w.dial(t)
		if out, err := find(t, conn, searchRequest{query: "' OR 1=1--"}); err != nil || out != "found ' OR 1=1--" {
			t.Fatalf("%q %v", out, err)
		}
		if got := b.received(); len(got) != 1 {
			t.Errorf("backend received %q", got)
		}
		if ev := w.events(t); len(ev) != 1 || ev[0].Action != "detect" || ev[0].Match.Location != "grpc" {
			t.Errorf("events %+v", ev)
		}
	})
	t.Run("rate limit", func(t *testing.T) {
		w, _ := startGRPCWAF(t, wafOptions{args: []string{"-rate-limit", "2/1m"}})
		conn := w.dial(t)
		for range 2 {
			if _, err := find(t, conn, searchRequest{query: "ok"}); err != nil {
				t.Fatal(err)
			}
		}
		_, err := find(t, conn, searchRequest{query: "ok"})
		if e := checkGRPCBlock(t, w, err, codes.ResourceExhausted); e.Reason != "rate_limit" {
			t.Errorf("event %+v", e)
		}
	})
	t.Run("bot", func(t *testing.T) {
		w, _ := startGRPCWAF(t, wafOptions{args: []string{"-bot-protection", "-bot-challenge-score", "1"}})
		_, err := find(t, w.dial(t), searchRequest{query: "ok"})
		if e := checkGRPCBlock(t, w, err, codes.PermissionDenied); e.Reason != "bot" {
			t.Errorf("event %+v", e)
		}
	})
}

// TestGRPCEngines runs gRPC calls through the CRS, which sees the
// metadata, and over HTTPS, where HTTP/2 is negotiated with TLS.
func TestGRPCEngines(t *testing.T) {
	w, b := startGRPCWAF(t, wafOptions{tls: true, args: []string{"-engine", "both"}})
	conn := w.dial(t)
	if out, err := find(t, conn, searchRequest{query: "over tls", filter: "blue", limit: 7}); err != nil || out != "found over tls" {
		t.Fatalf("clean call: %q %v\n%s", out, err, w.stderr)
	}
	_, err := find(t, conn, searchRequest{query: "<script>alert(1)</script>"})
	checkGRPCBlock(t, w, err, codes.PermissionDenied)

	ctx := metadata.AppendToOutgoingContext(grpcContext(t), "x-debug", "() { :; }; /bin/cat /etc/passwd")
	err = conn.Invoke(ctx, "/test.Search/Find", searchRequest{query: "ok"}.message(), dynamicpb.NewMessage(searchReplyMD))
	checkGRPCBlock(t, w, err, codes.PermissionDenied)

	w, _ = startGRPCWAF(t, wafOptions{args: []string{"-engine", "crs"}})
	if out, err := find(t, w.dial(t), searchRequest{query: "crs only"}); err != nil || out != "found crs only" {
		t.Fatalf("CRS only: %q %v\n%s", out, err, w.stderr)
	}
	if got := b.received(); !slices.Equal(got, []string{"over tls"}) {
		t.Errorf("backend received %q", got)
	}
}

// rawMessage and rawCodec send bytes that are not a valid message.
type rawMessage []byte

type rawCodec struct{}

func (rawCodec) Marshal(v any) (mem.BufferSlice, error) {
	return mem.BufferSlice{mem.SliceBuffer(v.(rawMessage))}, nil
}
func (rawCodec) Unmarshal(data mem.BufferSlice, v any) error {
	return proto.Unmarshal(data.Materialize(), v.(proto.Message))
}
func (rawCodec) Name() string { return "proto" }

// grpcWebFrame frames a message for gRPC-Web.
func grpcWebFrame(flags byte, msg []byte) []byte {
	b := make([]byte, 5, 5+len(msg))
	b[0] = flags
	b[1], b[2], b[3], b[4] = byte(len(msg)>>24), byte(len(msg)>>16), byte(len(msg)>>8), byte(len(msg))
	return append(b, msg...)
}

// TestGRPCWeb sends gRPC-Web calls over HTTP/1.1, binary and
// Base64-encoded, as browsers do, to a backend that speaks gRPC-Web (such
// as Envoy or a gRPC-Web wrapper).
func TestGRPCWeb(t *testing.T) {
	var mu sync.Mutex
	var got []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc-web-text") {
			body, _ = base64.StdEncoding.DecodeString(string(body))
		}
		m := dynamicpb.NewMessage(searchRequestType)
		if len(body) < 5 || proto.Unmarshal(body[5:], m) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		got = append(got, queryOf(m))
		mu.Unlock()
		out, _ := proto.Marshal(reply("found " + queryOf(m)))
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		w.Write(grpcWebFrame(0, out))
		w.Write(grpcWebFrame(0x80, []byte("grpc-status:0\r\n")))
	}))
	t.Cleanup(backend.Close)
	w := startWAF(t, wafOptions{backend: backend.URL})
	c := w.client(t, nil)

	call := func(contentType string, req searchRequest) response {
		msg, _ := proto.Marshal(req.message())
		body := grpcWebFrame(0, msg)
		if strings.Contains(contentType, "text") {
			body = []byte(base64.StdEncoding.EncodeToString(body))
		}
		return c.send(http.MethodPost, "/test.Search/Find", contentType, string(body), "X-Grpc-Web", "1")
	}
	for _, ct := range []string{"application/grpc-web+proto", "application/grpc-web-text"} {
		t.Run(ct, func(t *testing.T) {
			r := call(ct, searchRequest{query: "web"})
			if r.StatusCode != http.StatusOK || !strings.Contains(r.body, "found web") {
				t.Fatalf("clean call: %d %q", r.StatusCode, r.body)
			}
			r = call(ct, searchRequest{query: "web", filter: "javascript:alert(document.cookie)"})
			m := grpcEventRe.FindStringSubmatch(r.Header.Get("Grpc-Message"))
			if r.StatusCode != http.StatusOK || r.Header.Get("Grpc-Status") != "7" || m == nil || !strings.HasPrefix(r.Header.Get("Content-Type"), ct) {
				t.Fatalf("attack: %d %v", r.StatusCode, r.Header)
			}
			if e := w.eventByID(t, m[1]); e.Match == nil || e.Match.Field != "[0].2.1" {
				t.Errorf("event %+v", e.Match)
			}
		})
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(got, []string{"web", "web"}) {
		t.Errorf("backend received %q", got)
	}
}
