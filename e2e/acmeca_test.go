//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCA is an ACME CA (RFC 8555) for the tests. It validates challenges
// for real: HTTP-01 by fetching the key authorization from the address in
// httpAddr, and TLS-ALPN-01 by a handshake with tlsAddr, whatever the
// domain. JWS signatures are not checked.
type fakeCA struct {
	URL string // directory URL
	pki *pki

	mu         sync.Mutex
	mode       string        // see setMode
	lifetime   time.Duration // of issued certificates
	challenges []string      // challenge types offered
	httpAddr   string        // where HTTP-01 is validated
	tlsAddr    string        // where TLS-ALPN-01 is validated
	thumbprint string        // of the account key
	orders     map[string]*caOrder
	authzs     map[string]*caAuthz
	nextID     int
	requests   map[string]int // by endpoint, e.g. "order"
	issued     []*x509.Certificate
}

type caOrder struct {
	Status         string         `json:"status"`
	Identifiers    []caIdentifier `json:"identifiers"`
	Authorizations []string       `json:"authorizations"`
	Finalize       string         `json:"finalize"`
	Certificate    string         `json:"certificate,omitempty"`
	pem            []byte
}

type caIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type caAuthz struct {
	Status     string         `json:"status"`
	Identifier caIdentifier   `json:"identifier"`
	Challenges []*caChallenge `json:"challenges"`
}

type caChallenge struct {
	Type   string     `json:"type"`
	URL    string     `json:"url"`
	Token  string     `json:"token"`
	Status string     `json:"status"`
	Error  *caProblem `json:"error,omitempty"`
}

type caProblem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status,omitempty"`
}

// startCA starts a CA that issues certificates valid for 90 days and
// offers TLS-ALPN-01 and HTTP-01.
func startCA(t *testing.T) *fakeCA {
	t.Helper()
	ca := &fakeCA{
		pki:        newPKI(t),
		mode:       "ok",
		lifetime:   90 * 24 * time.Hour,
		challenges: []string{"tls-alpn-01", "http-01"},
		orders:     map[string]*caOrder{},
		authzs:     map[string]*caAuthz{},
		requests:   map[string]int{},
	}
	srv := httptest.NewServer(http.HandlerFunc(ca.serve))
	t.Cleanup(srv.Close)
	ca.URL = srv.URL + "/directory"
	return ca
}

// setMode sets how the CA answers certificate requests:
//
//	"ok"      validate the challenges and issue
//	"invalid" fail the validation as if the CA could not connect
//	"reject"  reject new orders, with detail in the problem
//	"down"    answer every request with 503
func (ca *fakeCA) setMode(mode string) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.mode = mode
}

// rejectDetail is the detail of rejected orders. The shell must not run
// what it contains when it reaches a notification command.
const rejectDetail = "Policy forbids $(touch PWNED1) `touch PWNED2` ; touch PWNED3"

func (ca *fakeCA) target(httpAddr, tlsAddr string) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.httpAddr, ca.tlsAddr = httpAddr, tlsAddr
}

// count returns the number of requests to an endpoint, e.g. "order".
func (ca *fakeCA) count(endpoint string) int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.requests[endpoint]
}

func (ca *fakeCA) certs() []*x509.Certificate {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return append([]*x509.Certificate(nil), ca.issued...)
}

func (ca *fakeCA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.pki.cert)
	return p
}

func (ca *fakeCA) serve(w http.ResponseWriter, r *http.Request) {
	base := "http://" + r.Host
	w.Header().Set("Replay-Nonce", fmt.Sprint(time.Now().UnixNano()))
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	endpoint := parts[0]

	ca.mu.Lock()
	ca.requests[endpoint]++
	mode := ca.mode
	ca.mu.Unlock()
	if mode == "down" && endpoint != "nonce" {
		http.Error(w, "maintenance", http.StatusServiceUnavailable)
		return
	}

	switch endpoint {
	case "directory":
		writeJSON(w, http.StatusOK, map[string]any{
			"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/order",
			"revokeCert": base + "/revoke", "keyChange": base + "/key-change",
			"meta": map[string]any{"termsOfService": base + "/terms"},
		})
		return
	case "nonce":
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		writeProblem(w, http.StatusMethodNotAllowed, "malformed", "POST only")
		return
	}
	hdr, payload, err := decodeJWS(r.Body)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()
	switch {
	case endpoint == "account":
		if jwk, ok := hdr["jwk"].(map[string]any); ok {
			ca.thumbprint = thumbprint(jwk)
		}
		w.Header().Set("Location", base+"/acct/1")
		writeJSON(w, http.StatusCreated, map[string]any{"status": "valid"})
	case endpoint == "acct":
		writeJSON(w, http.StatusOK, map[string]any{"status": "valid"})
	case endpoint == "order" && len(parts) == 1:
		if mode == "reject" {
			writeProblem(w, http.StatusBadRequest, "rejectedIdentifier", rejectDetail)
			return
		}
		var req struct {
			Identifiers []caIdentifier `json:"identifiers"`
		}
		json.Unmarshal(payload, &req)
		o := &caOrder{Status: "pending", Identifiers: req.Identifiers}
		for _, id := range req.Identifiers {
			z := &caAuthz{Status: "pending", Identifier: id}
			zid := ca.newID()
			for _, typ := range ca.challenges {
				cid := ca.newID()
				z.Challenges = append(z.Challenges, &caChallenge{Type: typ, URL: base + "/chal/" + zid + "/" + cid, Token: "tok" + cid, Status: "pending"})
			}
			ca.authzs[zid] = z
			o.Authorizations = append(o.Authorizations, base+"/authz/"+zid)
		}
		oid := ca.newID()
		o.Finalize = base + "/finalize/" + oid
		ca.orders[oid] = o
		w.Header().Set("Location", base+"/order/"+oid)
		writeJSON(w, http.StatusCreated, o)
	case endpoint == "order" && ca.orders[parts[1]] != nil:
		writeJSON(w, http.StatusOK, ca.updateOrder(ca.orders[parts[1]]))
	case endpoint == "authz" && ca.authzs[parts[1]] != nil:
		z := ca.authzs[parts[1]]
		if strings.Contains(string(payload), "deactivated") {
			z.Status = "deactivated"
		}
		writeJSON(w, http.StatusOK, z)
	case endpoint == "chal" && len(parts) == 3 && ca.authzs[parts[1]] != nil:
		z := ca.authzs[parts[1]]
		for _, c := range z.Challenges {
			if strings.HasSuffix(c.URL, "/"+parts[2]) {
				ca.validate(z, c, mode)
				writeJSON(w, http.StatusOK, c)
				return
			}
		}
		writeProblem(w, http.StatusNotFound, "malformed", "no such challenge")
	case endpoint == "finalize" && ca.orders[parts[1]] != nil:
		o := ca.updateOrder(ca.orders[parts[1]])
		if o.Status != "ready" {
			writeProblem(w, http.StatusForbidden, "orderNotReady", "order is "+o.Status)
			return
		}
		var req struct {
			CSR string `json:"csr"`
		}
		json.Unmarshal(payload, &req)
		der, _ := base64.RawURLEncoding.DecodeString(req.CSR)
		pemChain, err := ca.issue(der)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "badCSR", err.Error())
			return
		}
		o.Status, o.Certificate, o.pem = "valid", base+"/cert/"+parts[1], pemChain
		writeJSON(w, http.StatusOK, o)
	case endpoint == "cert" && ca.orders[parts[1]] != nil:
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(ca.orders[parts[1]].pem)
	default:
		writeProblem(w, http.StatusNotFound, "malformed", "not found: "+r.URL.Path)
	}
}

func (ca *fakeCA) newID() string {
	ca.nextID++
	return fmt.Sprint(ca.nextID)
}

// updateOrder makes a pending order ready once its authorizations are
// valid, or invalid if one is.
func (ca *fakeCA) updateOrder(o *caOrder) *caOrder {
	if o.Status != "pending" {
		return o
	}
	ready := true
	for _, u := range o.Authorizations {
		switch ca.authzs[u[strings.LastIndex(u, "/")+1:]].Status {
		case "invalid", "deactivated":
			o.Status = "invalid"
			return o
		case "pending":
			ready = false
		}
	}
	if ready {
		o.Status = "ready"
	}
	return o
}

// validate checks a challenge the client has accepted. It runs with the
// lock held; the tests do not need concurrent validations.
func (ca *fakeCA) validate(z *caAuthz, c *caChallenge, mode string) {
	if c.Status != "pending" {
		return
	}
	keyAuth := c.Token + "." + ca.thumbprint
	var err error
	switch {
	case mode == "invalid":
		err = fmt.Errorf("%s: Timeout during connect (likely firewall problem)", z.Identifier.Value)
	case c.Type == "http-01":
		err = validateHTTP01(ca.httpAddr, z.Identifier.Value, c.Token, keyAuth)
	case c.Type == "tls-alpn-01":
		err = validateTLSALPN01(ca.tlsAddr, z.Identifier.Value, keyAuth)
	}
	if err != nil {
		c.Status, z.Status = "invalid", "invalid"
		c.Error = &caProblem{Type: "urn:ietf:params:acme:error:connection", Detail: err.Error(), Status: 400}
		return
	}
	c.Status, z.Status = "valid", "valid"
}

func validateHTTP01(addr, domain, token, keyAuth string) error {
	if addr == "" {
		return fmt.Errorf("%s: connection refused on port 80", domain)
	}
	req, _ := http.NewRequest("GET", "http://"+addr+"/.well-known/acme-challenge/"+token, nil)
	req.Host = domain
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != keyAuth {
		return fmt.Errorf("%s: invalid response from http-01: %d %q", domain, resp.StatusCode, body)
	}
	return nil
}

// idPeAcmeIdentifier is the extension of a TLS-ALPN-01 certificate (RFC
// 8737).
var idPeAcmeIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

func validateTLSALPN01(addr, domain, keyAuth string) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{
		ServerName:         domain,
		NextProtos:         []string{"acme-tls/1"},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return fmt.Errorf("%s: tls-alpn-01: %w", domain, err)
	}
	defer conn.Close()
	st := conn.ConnectionState()
	if st.NegotiatedProtocol != "acme-tls/1" {
		return fmt.Errorf("%s: tls-alpn-01: protocol %q negotiated", domain, st.NegotiatedProtocol)
	}
	want := sha256.Sum256([]byte(keyAuth))
	for _, ext := range st.PeerCertificates[0].Extensions {
		var got []byte
		if ext.Id.Equal(idPeAcmeIdentifier) && ext.Critical {
			if _, err := asn1.Unmarshal(ext.Value, &got); err == nil && string(got) == string(want[:]) {
				return nil
			}
		}
	}
	return fmt.Errorf("%s: tls-alpn-01: wrong key authorization", domain)
}

// issue signs a CSR and returns the certificate and the CA's, in PEM.
func (ca *fakeCA) issue(der []byte) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: csr.DNSNames[0]},
		DNSNames:     csr.DNSNames,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(ca.lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.pki.cert, csr.PublicKey, ca.pki.key)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	ca.issued = append(ca.issued, leaf)
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	return append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.pki.cert.Raw})...), nil
}

// cacheCert writes a certificate for domain issued by the CA, with the
// validity period given, to the autocert cache of prismwaf in root, as if
// it had been obtained before.
func (ca *fakeCA) cacheCert(t *testing.T, root, domain string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.pki.cert, &key.PublicKey, ca.pki.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.pki.cert.Raw})...)
	dir := filepath.Join(root, cacheNamespace(ca.URL))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, domain), data, 0o600); err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

// cacheNamespace is the name of the cache directory of a CA, as in
// internal/tlsutil: "127.0.0.1-12345-directory".
func cacheNamespace(directoryURL string) string {
	s := strings.TrimPrefix(directoryURL, "http://")
	return strings.NewReplacer(":", "-", "/", "-").Replace(s)
}

func decodeJWS(r io.Reader) (map[string]any, []byte, error) {
	var msg struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
	}
	if err := json.NewDecoder(r).Decode(&msg); err != nil {
		return nil, nil, err
	}
	h, err := base64.RawURLEncoding.DecodeString(msg.Protected)
	if err != nil {
		return nil, nil, err
	}
	var hdr map[string]any
	if err := json.Unmarshal(h, &hdr); err != nil {
		return nil, nil, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(msg.Payload)
	return hdr, payload, err
}

// thumbprint returns the JWK thumbprint (RFC 7638) of an account key.
func thumbprint(jwk map[string]any) string {
	var s string
	if jwk["kty"] == "EC" {
		s = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, jwk["crv"], jwk["x"], jwk["y"])
	} else {
		s = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, jwk["e"], jwk["n"])
	}
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeProblem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(caProblem{Type: "urn:ietf:params:acme:error:" + typ, Detail: detail, Status: status})
}
