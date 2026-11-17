package grpc

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// maxDepth limits the nesting of messages that are decoded, like
// protobuf's default recursion limit.
const maxDepth = 100

// Schema holds the services and messages of a server, from protobuf
// descriptor sets.
type Schema struct {
	methods map[string]protoreflect.MethodDescriptor
}

// LoadSchema reads binary FileDescriptorSet files, as written by
// "protoc --include_imports --descriptor_set_out=FILE" or "buf build -o
// FILE".
func LoadSchema(paths []string) (*Schema, error) {
	set := &descriptorpb.FileDescriptorSet{}
	seen := map[string]bool{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("grpc: %w", err)
		}
		var fs descriptorpb.FileDescriptorSet
		if err := proto.Unmarshal(b, &fs); err != nil {
			return nil, fmt.Errorf("grpc: %s is not a FileDescriptorSet: %w", p, err)
		}
		for _, f := range fs.File {
			if !seen[f.GetName()] {
				seen[f.GetName()] = true
				set.File = append(set.File, f)
			}
		}
	}
	files, err := protodesc.NewFiles(set)
	if err != nil {
		return nil, fmt.Errorf("grpc: invalid descriptor set (generate it with --include_imports): %w", err)
	}
	s := &Schema{methods: map[string]protoreflect.MethodDescriptor{}}
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		for i := range fd.Services().Len() {
			sd := fd.Services().Get(i)
			for j := range sd.Methods().Len() {
				md := sd.Methods().Get(j)
				s.methods["/"+string(sd.FullName())+"/"+string(md.Name())] = md
			}
		}
		return true
	})
	if len(s.methods) == 0 {
		return nil, errors.New("grpc: the descriptor sets have no services")
	}
	return s, nil
}

// Method returns the method for a request path such as
// "/helloworld.Greeter/SayHello", or nil.
func (s *Schema) Method(path string) protoreflect.MethodDescriptor { return s.methods[path] }

// Services returns the full names of the services, sorted.
func (s *Schema) Services() []string {
	var out []string
	for _, md := range s.methods {
		name := string(md.Parent().FullName())
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// VisitFunc is called for each string in a message. path builds the
// location of the string, e.g. "user.name" or "1.2", and is only valid
// during the call. Returning an error ends the walk.
type VisitFunc func(value string, path func() string) error

// ErrInvalidMessage is returned by Walk for a message that does not match
// its type.
var ErrInvalidMessage = errors.New("grpc: invalid message")

// Walk calls visit for each string in a protobuf message. With the
// message type md, the message must match it, and the strings are its
// string fields, named as in the .proto file; fields that md does not
// have are decoded as without a type. Without a type, every
// length-delimited field may be a string, bytes or a message: if it
// decodes as a message, its fields are visited, named by their numbers,
// and it is visited as a string too. A message that does not decode at
// all is visited as a whole.
func Walk(msg []byte, md protoreflect.MessageDescriptor, visit VisitFunc) error {
	w := walker{visit: visit}
	if md == nil {
		if !w.isMessage(msg, 0) {
			return visit(string(msg), func() string { return "" })
		}
		return w.wire(msg, 0)
	}
	m := dynamicpb.NewMessage(md)
	if err := (proto.UnmarshalOptions{RecursionLimit: maxDepth}).Unmarshal(msg, m); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	return w.message(m, 0)
}

type walker struct {
	visit VisitFunc
	path  []string
}

func (w *walker) pathString() string {
	var b strings.Builder
	for i, s := range w.path {
		if i > 0 && !strings.HasPrefix(s, "[") {
			b.WriteByte('.')
		}
		b.WriteString(s)
	}
	return b.String()
}

func (w *walker) visitString(s string) error { return w.visit(s, w.pathString) }

func (w *walker) push(s string) { w.path = append(w.path, s) }
func (w *walker) pop()          { w.path = w.path[:len(w.path)-1] }

// message walks a decoded message.
func (w *walker) message(m protoreflect.Message, depth int) error {
	var err error
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		w.push(string(fd.Name()))
		defer w.pop()
		switch {
		case fd.IsList():
			l := v.List()
			for i := range l.Len() {
				w.push("[" + strconv.Itoa(i) + "]")
				err = w.value(fd, l.Get(i), depth)
				w.pop()
				if err != nil {
					break
				}
			}
		case fd.IsMap():
			v.Map().Range(func(k protoreflect.MapKey, mv protoreflect.Value) bool {
				key := k.String()
				w.push("[" + strconv.Quote(key) + "]")
				defer w.pop()
				if fd.MapKey().Kind() == protoreflect.StringKind {
					if err = w.visitString(key); err != nil {
						return false
					}
				}
				err = w.value(fd.MapValue(), mv, depth)
				return err == nil
			})
		default:
			err = w.value(fd, v, depth)
		}
		return err == nil
	})
	if err != nil {
		return err
	}
	u := m.GetUnknown()
	if len(u) == 0 {
		return nil
	}
	// The decoder keeps fields of the wrong wire type as unknown fields,
	// e.g. a string where the type has a number; the backend ignores them.
	fields := m.Descriptor().Fields()
	for b := u; len(b) > 0; {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		if fd := fields.ByNumber(num); fd != nil {
			return fmt.Errorf("%w: field %s (%d) has wire type %d", ErrInvalidMessage, w.fieldPath(string(fd.Name())), num, typ)
		}
		b = b[n:]
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			break
		}
		b = b[n:]
	}
	// Fields that the type does not have, e.g. from a newer client.
	if w.isMessage(u, depth) {
		return w.wire(u, depth)
	}
	return nil
}

// fieldPath returns the path of a field of the current message.
func (w *walker) fieldPath(name string) string {
	w.push(name)
	defer w.pop()
	return w.pathString()
}

func (w *walker) value(fd protoreflect.FieldDescriptor, v protoreflect.Value, depth int) error {
	switch fd.Kind() {
	case protoreflect.StringKind:
		return w.visitString(v.String())
	case protoreflect.BytesKind:
		return w.visitString(string(v.Bytes()))
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return w.message(v.Message(), depth+1)
	}
	return nil
}

// wire walks a message without a type, which isMessage has checked.
func (w *walker) wire(b []byte, depth int) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		b = b[n:]
		n = protowire.ConsumeFieldValue(num, typ, b)
		if typ == protowire.BytesType {
			v, _ := protowire.ConsumeBytes(b)
			w.push(strconv.Itoa(int(num)))
			// The fields first, for a precise path, then the whole value:
			// what decodes as a message may be a string to the backend.
			var err error
			if depth < maxDepth && w.isMessage(v, depth+1) {
				err = w.wire(v, depth+1)
			}
			if err == nil {
				err = w.visitString(string(v))
			}
			w.pop()
			if err != nil {
				return err
			}
		}
		b = b[n:]
	}
	return nil
}

// isMessage reports whether b decodes as a non-empty message.
func (w *walker) isMessage(b []byte, depth int) bool {
	if len(b) == 0 || depth >= maxDepth {
		return false
	}
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 || num > protowire.MaxValidNumber {
			return false
		}
		b = b[n:]
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return false
		}
		b = b[n:]
	}
	return true
}
