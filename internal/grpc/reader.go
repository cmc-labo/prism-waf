package grpc

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Flags of a message frame. gRPC-Web marks the trailers that end a
// response with trailerFlag; requests have none.
const (
	compressedFlag = 0x01
	trailerFlag    = 0x80
)

// headerSize is the size of a frame header: the flags and the length of
// the message as a 32-bit big-endian integer.
const headerSize = 5

// Errors reported in Message.Err.
var (
	ErrInvalid             = errors.New("grpc: invalid message frame")
	ErrUnsupportedEncoding = errors.New("grpc: unsupported message encoding")
)

// Message is a message of a request stream, or a problem with one.
type Message struct {
	// Index counts the messages of the stream from 0.
	Index int
	// Data is the message, decompressed, unless TooLarge or Err is set.
	Data []byte
	// TooLarge reports that the message, or its decompressed form, is
	// larger than the limit. Size is its size, or the limit + 1 if the
	// decompressed size is not known.
	TooLarge bool
	Size     int
	// Err is set for a stream that cannot be decoded, e.g. ErrInvalid. No
	// more messages follow.
	Err error
}

// MessageFunc is called with each message of a stream. An error ends the
// stream: it is returned to the reader of the stream instead of the data
// that completes the message. If it returns nil for a message that is
// TooLarge, the message is skipped; for a message with Err, the rest of
// the stream is passed on without being inspected.
type MessageFunc func(Message) error

// Reader passes a request body through while it splits it into messages.
// The bytes that complete a message are only returned once the message
// has been passed to the MessageFunc, so the backend never receives a
// whole message that was not inspected, while streaming calls keep
// flowing message by message.
type Reader struct {
	body     io.ReadCloser
	text     bool
	encoding string
	max      int
	fn       MessageFunc

	err         error // returned by every Read once set
	passthrough bool

	// Base64 characters of an incomplete group, for WebText.
	group []byte

	header     [headerSize]byte
	nheader    int
	inMessage  bool
	compressed bool
	remaining  int
	skip       bool // the message is too large and is not inspected
	data       []byte
	index      int
}

// NewReader returns a Reader for the body of a request of protocol p.
// encoding is the grpc-encoding header, the compression of compressed
// messages; gzip and deflate are supported. maxSize limits the size of a
// message, compressed and decompressed.
func NewReader(body io.ReadCloser, p Protocol, encoding string, maxSize int, fn MessageFunc) *Reader {
	return &Reader{body: body, text: p == WebText, encoding: encoding, max: maxSize, fn: fn}
}

// Read implements io.Reader.
func (r *Reader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.body.Read(p)
	if n > 0 && !r.passthrough {
		if ferr := r.write(p[:n]); ferr != nil {
			r.err = ferr
			return 0, ferr
		}
	}
	return n, err
}

// Close implements io.Closer.
func (r *Reader) Close() error { return r.body.Close() }

func (r *Reader) write(b []byte) error {
	if !r.text {
		return r.feed(b)
	}
	// Base64 in groups of four characters. Each chunk of the stream may
	// end with padding, so groups are decoded one at a time.
	for len(b) > 0 {
		k := min(4-len(r.group), len(b))
		r.group = append(r.group, b[:k]...)
		b = b[k:]
		if len(r.group) < 4 {
			return nil
		}
		var out [3]byte
		n, err := base64.StdEncoding.Decode(out[:], r.group)
		r.group = r.group[:0]
		if err != nil {
			return r.fail(fmt.Errorf("%w: invalid Base64: %v", ErrInvalid, err))
		}
		if err := r.feed(out[:n]); err != nil || r.passthrough {
			return err
		}
	}
	return nil
}

// feed parses frames.
func (r *Reader) feed(b []byte) error {
	for len(b) > 0 && !r.passthrough {
		if !r.inMessage {
			k := copy(r.header[r.nheader:], b)
			r.nheader += k
			b = b[k:]
			if r.nheader < headerSize {
				return nil
			}
			r.nheader = 0
			flags := r.header[0]
			if flags&^compressedFlag != 0 {
				return r.fail(fmt.Errorf("%w: flags %#x", ErrInvalid, flags))
			}
			size := binary.BigEndian.Uint32(r.header[1:])
			r.inMessage, r.compressed, r.skip = true, flags&compressedFlag != 0, false
			r.data = r.data[:0]
			if uint64(size) > uint64(r.max) {
				if err := r.fn(Message{Index: r.index, TooLarge: true, Size: int(min(size, 1<<31-1))}); err != nil {
					return err
				}
				r.skip = true
			}
			r.remaining = int(size)
		}
		k := min(len(b), r.remaining)
		if !r.skip {
			r.data = append(r.data, b[:k]...)
		}
		b = b[k:]
		r.remaining -= k
		if r.remaining == 0 {
			if err := r.finish(); err != nil {
				return err
			}
		}
	}
	return nil
}

// finish passes on a complete message.
func (r *Reader) finish() error {
	r.inMessage = false
	defer func() { r.index++ }()
	if r.skip {
		return nil
	}
	data := r.data
	if r.compressed {
		var err error
		data, err = r.decompress(data)
		switch {
		case errors.Is(err, errTooLarge):
			return r.fn(Message{Index: r.index, TooLarge: true, Size: r.max + 1})
		case err != nil:
			return r.fail(err)
		}
	}
	return r.fn(Message{Index: r.index, Data: data, Size: len(data)})
}

var errTooLarge = errors.New("grpc: message too large")

func (r *Reader) decompress(data []byte) ([]byte, error) {
	var zr io.Reader
	var err error
	switch r.encoding {
	case "gzip":
		zr, err = gzip.NewReader(bytes.NewReader(data))
	case "deflate":
		zr, err = zlib.NewReader(bytes.NewReader(data))
	case "", "identity":
		return nil, fmt.Errorf("%w: compressed message without grpc-encoding", ErrInvalid)
	default:
		return nil, fmt.Errorf("%w %q", ErrUnsupportedEncoding, r.encoding)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, r.encoding, err)
	}
	// A small message can decompress to a huge one.
	out, err := io.ReadAll(io.LimitReader(zr, int64(r.max)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, r.encoding, err)
	}
	if len(out) > r.max {
		return nil, errTooLarge
	}
	return out, nil
}

// fail reports a stream that cannot be decoded.
func (r *Reader) fail(err error) error {
	if ferr := r.fn(Message{Index: r.index, Err: err}); ferr != nil {
		return ferr
	}
	r.passthrough = true
	return nil
}

func putLength(b []byte, n int) { binary.BigEndian.PutUint32(b, uint32(n)) }

func encodeBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
