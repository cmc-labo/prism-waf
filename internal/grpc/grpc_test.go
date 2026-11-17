package grpc

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

func frame(flags byte, msg []byte) []byte {
	b := []byte{flags, 0, 0, 0, 0}
	putLength(b[1:], len(msg))
	return append(b, msg...)
}

func gzipped(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	zw.Close()
	return buf.Bytes()
}

// chunks returns a reader that returns data n bytes at a time.
type chunks struct {
	data []byte
	n    int
}

func (c *chunks) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	k := min(c.n, len(p), len(c.data))
	copy(p, c.data[:k])
	c.data = c.data[k:]
	return k, nil
}

// read reads a stream through a Reader that records the messages, in
// chunks of every size.
func read(t *testing.T, p Protocol, encoding string, max int, data []byte, fn func(Message) error) []Message {
	t.Helper()
	var first []Message
	for _, n := range []int{1, 2, 3, 5, 7, 1 << 20} {
		var got []Message
		r := NewReader(io.NopCloser(&chunks{data: data, n: n}), p, encoding, max, func(m Message) error {
			m.Data = slices.Clone(m.Data)
			got = append(got, m)
			if fn != nil {
				return fn(m)
			}
			return nil
		})
		out, err := io.ReadAll(r)
		if err == nil && !bytes.Equal(out, data) {
			t.Fatalf("chunks of %d: passed %q, want %q", n, out, data)
		}
		if first == nil {
			first = got
		} else if len(got) != len(first) {
			t.Fatalf("chunks of %d: %d messages, %d with chunks of 1", n, len(got), len(first))
		}
	}
	return first
}

func TestReader(t *testing.T) {
	var data []byte
	data = append(data, frame(0, []byte("first"))...)
	data = append(data, frame(0, nil)...)
	data = append(data, frame(1, gzipped([]byte("second")))...)
	got := read(t, GRPC, "gzip", 100, data, nil)
	want := []string{"first", "", "second"}
	if len(got) != len(want) {
		t.Fatalf("messages %+v", got)
	}
	for i, m := range got {
		if m.Index != i || string(m.Data) != want[i] || m.TooLarge || m.Err != nil {
			t.Errorf("message %d: %+v", i, m)
		}
	}

	// deflate is zlib.
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	zw.Write([]byte("deflated"))
	zw.Close()
	if got := read(t, GRPC, "deflate", 100, frame(1, buf.Bytes()), nil); len(got) != 1 || string(got[0].Data) != "deflated" {
		t.Errorf("deflate: %+v", got)
	}
}

// TestReaderHoldsBack checks that the bytes that complete a message are
// returned only after the message was inspected, and not at all when the
// inspection fails.
func TestReaderHoldsBack(t *testing.T) {
	data := append(frame(0, []byte("ok")), frame(0, []byte("attack"))...)
	blocked := errors.New("blocked")
	for _, n := range []int{1, 4, 8, 100} {
		var passed []byte
		r := NewReader(io.NopCloser(&chunks{data: data, n: n}), GRPC, "", 100, func(m Message) error {
			if string(m.Data) == "attack" {
				return blocked
			}
			return nil
		})
		buf := make([]byte, 64)
		var err error
		for err == nil {
			var k int
			k, err = r.Read(buf)
			passed = append(passed, buf[:k]...)
		}
		if !errors.Is(err, blocked) || len(passed) >= len(data) || !bytes.HasPrefix(data, passed) {
			t.Errorf("chunks of %d: passed %q, error %v", n, passed, err)
		}
		if _, err := r.Read(buf); !errors.Is(err, blocked) {
			t.Errorf("chunks of %d: next read: %v", n, err)
		}
	}
}

func TestReaderTooLarge(t *testing.T) {
	data := append(frame(0, []byte("0123456789")), frame(0, []byte("ok"))...)
	got := read(t, GRPC, "", 5, data, nil)
	if len(got) != 2 || !got[0].TooLarge || got[0].Size != 10 || got[0].Data != nil || string(got[1].Data) != "ok" || got[1].Index != 1 {
		t.Errorf("messages %+v", got)
	}
	// A compressed message is limited after decompression, too.
	bomb := gzipped(bytes.Repeat([]byte{' '}, 100_000))
	got = read(t, GRPC, "gzip", 1000, frame(1, bomb), nil)
	if len(bomb) > 1000 || len(got) != 1 || !got[0].TooLarge || got[0].Size != 1001 {
		t.Errorf("bomb of %d bytes: %+v", len(bomb), got)
	}
	// Decompression stops at the limit: the end of this stream, which is
	// cut off, is never read.
	got = read(t, GRPC, "gzip", 1000, frame(1, bomb[:len(bomb)-10]), nil)
	if len(got) != 1 || !got[0].TooLarge {
		t.Errorf("cut bomb: %+v", got)
	}
}

// TestReaderLastEmptyMessage checks that an empty message at the end of a
// stream, such as the request of a unary call without fields, is passed
// to the MessageFunc too.
func TestReaderLastEmptyMessage(t *testing.T) {
	got := read(t, GRPC, "", 100, append(frame(0, []byte("a")), frame(0, nil)...), nil)
	if len(got) != 2 || got[1].Index != 1 || len(got[1].Data) != 0 {
		t.Errorf("messages %+v", got)
	}
}

func TestReaderErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		encoding string
		data     []byte
		want     error
	}{
		{"flags", "", frame(0x80, []byte("x")), ErrInvalid},
		{"compressed without encoding", "", frame(1, []byte("x")), ErrInvalid},
		{"not gzip", "gzip", frame(1, []byte("plain")), ErrInvalid},
		{"truncated gzip", "gzip", frame(1, gzipped([]byte("hello"))[:12]), ErrInvalid},
		{"snappy", "snappy", frame(1, []byte("x")), ErrUnsupportedEncoding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := append(tc.data, frame(0, []byte("after"))...)
			got := read(t, GRPC, tc.encoding, 100, data, nil)
			// No more messages after an error: the rest passes through.
			if len(got) != 1 || !errors.Is(got[0].Err, tc.want) {
				t.Errorf("messages %+v", got)
			}
		})
	}
	// Uncompressed messages need no supported encoding.
	if got := read(t, GRPC, "zstd", 100, frame(0, []byte("plain")), nil); len(got) != 1 || string(got[0].Data) != "plain" {
		t.Errorf("uncompressed: %+v", got)
	}
}

func TestReaderWebText(t *testing.T) {
	// Each chunk of the stream may have its own padding.
	text := base64.StdEncoding.EncodeToString(frame(0, []byte("a"))) +
		base64.StdEncoding.EncodeToString(frame(0, []byte("bc"))) +
		base64.StdEncoding.EncodeToString(frame(0, []byte("def")))
	if !strings.Contains(text, "=") {
		t.Fatal("no padding")
	}
	got := read(t, WebText, "", 100, []byte(text), nil)
	if len(got) != 3 || string(got[0].Data) != "a" || string(got[1].Data) != "bc" || string(got[2].Data) != "def" {
		t.Errorf("messages %+v", got)
	}
	got = read(t, WebText, "", 100, []byte("AAAA!!!!"), nil)
	if len(got) != 1 || !errors.Is(got[0].Err, ErrInvalid) {
		t.Errorf("invalid Base64: %+v", got)
	}
}

func TestProtocolOf(t *testing.T) {
	for _, tc := range []struct {
		method, contentType string
		p                   Protocol
		c                   Codec
	}{
		{"POST", "application/grpc", GRPC, Proto},
		{"POST", "application/grpc+proto", GRPC, Proto},
		{"POST", "application/grpc+json", GRPC, JSON},
		{"POST", "Application/GRPC; charset=utf-8", GRPC, Proto},
		{"POST", "application/grpc-web", Web, Proto},
		{"POST", "application/grpc-web+proto", Web, Proto},
		{"POST", "application/grpc-web-text", WebText, Proto},
		{"POST", "application/grpc-web-text+proto", WebText, Proto},
		{"GET", "application/grpc", None, Proto},
		{"POST", "application/json", None, Proto},
		{"POST", "application/grpcx", None, Proto},
		{"POST", "", None, Proto},
	} {
		r := httptest.NewRequest(tc.method, "/s/M", nil)
		r.Header.Set("Content-Type", tc.contentType)
		if p, c := ProtocolOf(r); p != tc.p || c != tc.c {
			t.Errorf("%s %q: %v %v", tc.method, tc.contentType, p, c)
		}
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	WriteError(w, GRPC, PermissionDenied, "Forbidden; event ID: 1 ü%")
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/grpc" ||
		w.Header().Get("Grpc-Status") != "7" || w.Header().Get("Grpc-Message") != "Forbidden; event ID: 1 %C3%BC%25" || w.Body.Len() != 0 {
		t.Errorf("%d %v %q", w.Code, w.Header(), w.Body)
	}
	w = httptest.NewRecorder()
	WriteError(w, WebText, ResourceExhausted, "x")
	if w.Header().Get("Content-Type") != "application/grpc-web-text+proto" || w.Header().Get("Grpc-Status") != "8" {
		t.Errorf("%v", w.Header())
	}

	w = httptest.NewRecorder()
	WriteTrailer(w, Web, PermissionDenied, "no")
	if want := frame(trailerFlag, []byte("grpc-status:7\r\ngrpc-message:no\r\n")); !bytes.Equal(w.Body.Bytes(), want) {
		t.Errorf("trailer frame %q", w.Body)
	}
	w = httptest.NewRecorder()
	WriteTrailer(w, GRPC, PermissionDenied, "no")
	if w.Header().Get(http.TrailerPrefix+"Grpc-Status") != "7" {
		t.Errorf("trailers %v", w.Header())
	}

	for code, want := range map[int]int{400: 3, 403: 7, 401: 7, 404: 12, 413: 8, 429: 8, 500: 13, 502: 14, 503: 14} {
		if got := StatusFromHTTP(code); got != want {
			t.Errorf("StatusFromHTTP(%d) = %d", code, got)
		}
	}
}

// testFile is
//
//	package t;
//	message Inner { string name = 1; bytes data = 2; }
//	message Req { string q = 1; Inner inner = 2; repeated string tags = 3; int32 n = 4;
//	              map<string, string> labels = 5; repeated Inner items = 6; }
//	service S { rpc Do(Req) returns (Req); }
var testFile = &descriptorpb.FileDescriptorProto{
	Name: proto.String("t.proto"), Package: proto.String("t"), Syntax: proto.String("proto3"),
	MessageType: []*descriptorpb.DescriptorProto{
		{Name: proto.String("Inner"), Field: []*descriptorpb.FieldDescriptorProto{
			fieldProto("name", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", false),
			fieldProto("data", 2, descriptorpb.FieldDescriptorProto_TYPE_BYTES, "", false),
		}},
		{Name: proto.String("Req"), Field: []*descriptorpb.FieldDescriptorProto{
			fieldProto("q", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", false),
			fieldProto("inner", 2, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, ".t.Inner", false),
			fieldProto("tags", 3, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", true),
			fieldProto("n", 4, descriptorpb.FieldDescriptorProto_TYPE_INT32, "", false),
			fieldProto("labels", 5, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, ".t.Req.LabelsEntry", true),
			fieldProto("items", 6, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, ".t.Inner", true),
		}, NestedType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("LabelsEntry"),
			Field: []*descriptorpb.FieldDescriptorProto{
				fieldProto("key", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", false),
				fieldProto("value", 2, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", false),
			},
			Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
		}}},
	},
	Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("S"), Method: []*descriptorpb.MethodDescriptorProto{{
		Name: proto.String("Do"), InputType: proto.String(".t.Req"), OutputType: proto.String(".t.Req"),
	}}}},
}

func fieldProto(name string, num int32, typ descriptorpb.FieldDescriptorProto_Type, typeName string, repeated bool) *descriptorpb.FieldDescriptorProto {
	f := &descriptorpb.FieldDescriptorProto{Name: proto.String(name), JsonName: proto.String(name), Number: proto.Int32(num), Type: typ.Enum(),
		Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()}
	if repeated {
		f.Label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	}
	if typeName != "" {
		f.TypeName = proto.String(typeName)
	}
	return f
}

func loadTestSchema(t *testing.T) *Schema {
	t.Helper()
	b, _ := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{testFile}})
	path := filepath.Join(t.TempDir(), "t.binpb")
	os.WriteFile(path, b, 0o644)
	// The same file twice, as in two sets of one build.
	s, err := LoadSchema([]string{path, path})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// message encodes fields: numbers with strings, []byte or nested
// messages.
func message(fields ...any) []byte {
	var b []byte
	for i := 0; i+1 < len(fields); i += 2 {
		num := protowire.Number(fields[i].(int))
		switch v := fields[i+1].(type) {
		case string:
			b = protowire.AppendTag(b, num, protowire.BytesType)
			b = protowire.AppendString(b, v)
		case []byte:
			b = protowire.AppendTag(b, num, protowire.BytesType)
			b = protowire.AppendBytes(b, v)
		case int:
			b = protowire.AppendTag(b, num, protowire.VarintType)
			b = protowire.AppendVarint(b, uint64(v))
		}
	}
	return b
}

func walk(t *testing.T, msg []byte, md protoreflect.MessageDescriptor) ([]string, error) {
	t.Helper()
	var got []string
	err := Walk(msg, md, func(value string, path func() string) error {
		got = append(got, path()+"="+value)
		return nil
	})
	return got, err
}

func TestWalkWithoutSchema(t *testing.T) {
	inner := message(1, "alice", 2, []byte{0xff, 0xfe})
	msg := message(1, "query", 2, inner, 3, "a", 3, "b", 4, 7)
	got, err := walk(t, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1=query", "2.1=alice", "2.2=\xff\xfe", "2=" + string(inner), "3=a", "3=b"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
	// Not a message: inspected as a whole.
	if got, _ := walk(t, []byte("' OR 1=1--"), nil); !slices.Equal(got, []string{"=' OR 1=1--"}) {
		t.Errorf("not a message: %q", got)
	}
	// A string that also decodes as a message, with the payload in
	// fixed64 fields that are not visited, is visited as a string.
	sneaky := "\x09' OR 1=\x091--     "
	got, _ = walk(t, message(1, sneaky), nil)
	if !slices.Contains(got, "1="+sneaky) {
		t.Errorf("sneaky: %q", got)
	}
}

func TestWalkWithSchema(t *testing.T) {
	s := loadTestSchema(t)
	md := s.Method("/t.S/Do")
	if md == nil || !slices.Equal(s.Services(), []string{"t.S"}) {
		t.Fatalf("method %v, services %v", md, s.Services())
	}
	in := md.Input()
	entry := message(1, "env", 2, "prod")
	msg := message(1, "query", 2, message(1, "alice", 2, []byte("bin")), 3, "a", 3, "b", 4, 7, 5, entry, 6, message(1, "i0"), 6, message(1, "i1"), 99, "new field")
	got, err := walk(t, msg, in)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	want := []string{"99=new field", "inner.data=bin", "inner.name=alice", "items[0].name=i0", "items[1].name=i1", `labels["env"]=env`, `labels["env"]=prod`, "q=query", "tags[0]=a", "tags[1]=b"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}

	for _, tc := range []struct {
		name string
		msg  []byte
		want string
	}{
		{"wire type", message(4, "seven"), "field n (4)"},
		{"nested wire type", message(2, message(1, 5)), "field inner.name (1)"},
		{"invalid UTF-8", message(1, string([]byte{0xff})), "UTF-8"},
		{"truncated", message(1, "query")[:3], "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := walk(t, tc.msg, in)
			if !errors.Is(err, ErrInvalidMessage) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v", err)
			}
		})
	}
}

func TestCheckMethod(t *testing.T) {
	s := loadTestSchema(t)
	for _, tc := range []struct {
		cfg       Config
		path      string
		violation string
		md        bool
	}{
		{Config{}, "/any.Service/Method", "", false},
		{Config{}, "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", ViolationReflection, false},
		{Config{}, "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", ViolationReflection, false},
		{Config{Reflection: true}, "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", "", false},
		{Config{Schema: s}, "/t.S/Do", "", true},
		{Config{Schema: s}, "/t.S/Delete", ViolationUnknownMethod, false},
		{Config{Schema: s}, "/t.s/do", ViolationUnknownMethod, false},
		{Config{Schema: s}, "/grpc.health.v1.Health/Check", "", false},
		{Config{Schema: s, Reflection: true}, "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", "", false},
	} {
		v, md := New(tc.cfg).CheckMethod(tc.path)
		if v != tc.violation || (md != nil) != tc.md {
			t.Errorf("%+v %s: %q %v", tc.cfg, tc.path, v, md)
		}
	}
}

func TestLoadSchemaErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0o644)
		return p
	}
	// A file whose import is missing: generated without --include_imports.
	dep := proto.Clone(testFile).(*descriptorpb.FileDescriptorProto)
	dep.Dependency = []string{"google/protobuf/empty.proto"}
	b, _ := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{dep}})
	noServices, _ := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{Name: proto.String("x.proto")}}})
	for _, tc := range []struct {
		path, want string
	}{
		{filepath.Join(dir, "missing"), "no such file"},
		{write("text", []byte("syntax = \"proto3\";")), "not a FileDescriptorSet"},
		{write("imports", b), "--include_imports"},
		{write("empty", noServices), "no services"},
	} {
		if _, err := LoadSchema([]string{tc.path}); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.path, err)
		}
	}
}
