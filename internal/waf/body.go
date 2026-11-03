package waf

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"mime"
	"regexp"
	"strconv"
	"strings"
)

// bodyFormat is how a request body is parsed for inspection.
type bodyFormat int

const (
	formatRaw bodyFormat = iota
	formatJSON
	formatXML
)

// bodyFormatOf returns the format for a Content-Type header value:
// application/json and application/*+json are JSON; application/xml,
// text/xml and application/*+xml (e.g. SOAP) are XML.
func bodyFormatOf(contentType string) bodyFormat {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return formatRaw
	}
	switch {
	case mt == "application/json" || strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json"):
		return formatJSON
	case mt == "application/xml" || mt == "text/xml" || strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+xml"):
		return formatXML
	}
	return formatRaw
}

// errStopWalk is returned by a visit function to end a walk early.
var errStopWalk = errors.New("waf: stop walk")

// visitFunc is called for each value found in a structured body. path
// builds the location of the value in the document and is only valid
// during the call. It is meant to be called only for values that match, so
// that deeply nested documents do not cost a path string per value.
// Returning an error such as errStopWalk ends the walk.
type visitFunc func(value string, path func() string) error

// walkJSON calls visit for every string in a JSON document: object keys
// and string values, including duplicate keys that a decoder into a map
// would drop. Paths look like $.user.name and $.items[2]. It returns an
// error if data is not valid JSON, including trailing garbage after the
// document.
func walkJSON(data []byte, visit visitFunc) error {
	type frame struct {
		object    bool
		expectKey bool
		key       string
		index     int
	}
	var stack []frame
	path := func() string {
		var b strings.Builder
		b.WriteByte('$')
		for _, f := range stack {
			if f.object {
				writeJSONKey(&b, f.key)
			} else {
				b.WriteString("[" + strconv.Itoa(f.index) + "]")
			}
		}
		return b.String()
	}
	// beginValue and endValue keep the position in the enclosing container
	// up to date.
	beginValue := func() {
		if n := len(stack); n > 0 && !stack[n-1].object {
			stack[n-1].index++
		}
	}
	endValue := func() {
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].expectKey = true
		}
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if len(stack) > 0 {
				return io.ErrUnexpectedEOF
			}
			return nil
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				beginValue()
				stack = append(stack, frame{object: t == '{', expectKey: t == '{', index: -1})
			case '}', ']':
				stack = stack[:len(stack)-1]
				endValue()
			}
		case string:
			if n := len(stack); n > 0 && stack[n-1].expectKey {
				stack[n-1].key = t
				stack[n-1].expectKey = false
				if err := visit(t, path); err != nil {
					return err
				}
				continue
			}
			beginValue()
			if err := visit(t, path); err != nil {
				return err
			}
			endValue()
		default: // number, bool or null
			beginValue()
			endValue()
		}
	}
}

var jsonIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

func writeJSONKey(b *strings.Builder, key string) {
	if jsonIdent.MatchString(key) {
		b.WriteString("." + key)
	} else {
		b.WriteString("[" + strconv.Quote(key) + "]")
	}
}

// walkXML calls visit for the text of every element, every attribute
// value, every start tag without its attribute values (so that markup such
// as event handler attributes is still inspected), comments, processing
// instructions and DTD declarations. Paths look like /order/item/name and /order/item/@id.
//
// The text of an element is collected across CDATA sections, entity
// references and comments, so that a payload split by them is inspected as
// a whole. It returns an error if data is not well-formed XML, including
// references to entities other than the five predefined ones, which only a
// DTD can declare.
func walkXML(data []byte, visit visitFunc) error {
	var stack []string
	elemPath := func() string { return "/" + strings.Join(stack, "/") }
	// childPath returns a function for the path of a node in the current
	// element, e.g. its comments.
	childPath := func(node string) func() string {
		return func() string {
			if len(stack) == 0 {
				return "/" + node
			}
			return elemPath() + "/" + node
		}
	}
	var text strings.Builder
	flush := func() error {
		defer text.Reset()
		if strings.TrimSpace(text.String()) == "" {
			return nil
		}
		return visit(text.String(), elemPath)
	}

	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return flush()
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if err := flush(); err != nil {
				return err
			}
			stack = append(stack, t.Name.Local)
			for _, a := range t.Attr {
				if err := visit(a.Value, childPath("@"+attrName(a))); err != nil {
					return err
				}
			}
			if err := visit(startTag(t), elemPath); err != nil {
				return err
			}
		case xml.EndElement:
			if err := flush(); err != nil {
				return err
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			text.Write(t)
		case xml.Comment:
			// A comment does not end the surrounding text.
			if err := visit(string(t), childPath("comment()")); err != nil {
				return err
			}
		case xml.ProcInst:
			if err := visit("<?"+t.Target+" "+string(t.Inst)+"?>", childPath("processing-instruction()")); err != nil {
				return err
			}
		case xml.Directive:
			if err := visit("<!"+string(t)+">", func() string { return "<!DOCTYPE>" }); err != nil {
				return err
			}
		}
	}
}

// startTag reconstructs the markup of a start element, such as
// <img src="" onerror="">. Attribute values are left out because they are
// inspected on their own; the tag catches markup that is dangerous by its
// names, like event handler attributes.
func startTag(e xml.StartElement) string {
	var b strings.Builder
	b.WriteString("<" + e.Name.Local)
	for _, a := range e.Attr {
		b.WriteString(" " + attrName(a) + `=""`)
	}
	b.WriteString(">")
	return b.String()
}

// attrName returns the local name of an attribute, keeping the xmlns:
// prefix of namespace declarations. Other prefixes are already resolved to
// namespace URLs by the decoder and are dropped.
func attrName(a xml.Attr) string {
	if a.Name.Space == "xmlns" {
		return "xmlns:" + a.Name.Local
	}
	return a.Name.Local
}
