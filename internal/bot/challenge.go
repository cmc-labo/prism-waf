package bot

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// ServeChallenge answers a request that has to solve a challenge first.
// GET and HEAD requests get a page with the proof-of-work challenge or the
// CAPTCHA, which then reloads the requested URL; other requests cannot be
// repeated after a challenge and get a plain 403 Forbidden.
func (g *Guard) ServeChallenge(w http.ResponseWriter, r *http.Request, d Decision) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeForbidden(w, "This request needs a browser check. Reload the page and try again.", d.EventID)
		return
	}
	g.writePage(w, r, pageData{Redirect: safeRedirect(r.URL.RequestURI()), EventID: d.EventID, Captcha: d.Captcha}, d.Client)
}

// ServeVerify handles the solution of a challenge, posted to VerifyPath.
// If it is correct, the client gets a clearance cookie and is redirected
// to the page it requested.
func (g *Guard) ServeVerify(w http.ResponseWriter, r *http.Request, clientIP string, secure bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	client := clientKey(clientIP)
	redirect := safeRedirect(r.PostForm.Get("r"))
	if r.PostForm.Has("captcha") {
		g.verifyCaptcha(w, r, clientIP, secure, redirect)
		return
	}
	switch err := g.verify(r.PostForm.Get("c"), r.PostForm.Get("n"), client, r.UserAgent()); {
	case err == nil:
		http.SetCookie(w, g.clearanceCookie(client, r.UserAgent(), levelPoW, secure))
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, redirect, http.StatusSeeOther)
	case errors.Is(err, errExpired):
		// E.g. a tab that was left open: solve a new challenge.
		g.writePage(w, r, pageData{Redirect: redirect}, client)
	default:
		// A new address or User-Agent, or a broken client. Do not solve
		// again automatically, which could loop forever.
		g.writePage(w, r, pageData{Redirect: redirect, Failed: true}, client)
	}
}

// verifyCaptcha handles the solution of a CAPTCHA.
func (g *Guard) verifyCaptcha(w http.ResponseWriter, r *http.Request, clientIP string, secure bool, redirect string) {
	client := clientKey(clientIP)
	failed := pageData{Redirect: redirect, Failed: true, Message: "The CAPTCHA could not be verified."}
	if g.captcha == nil {
		g.writePage(w, r, failed, client)
		return
	}
	err := g.captcha.verify(r.Context(), r.PostForm.Get("captcha"), clientIP, r.Host)
	switch {
	case err == nil:
		http.SetCookie(w, g.clearanceCookie(client, r.UserAgent(), levelCaptcha, secure))
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, redirect, http.StatusSeeOther)
		return
	case errors.Is(err, errCaptchaConfig), errors.Is(err, errCaptchaUnavailable):
		// Every user is affected: tell the administrator.
		g.logger.Warn("cannot verify CAPTCHA solutions", "provider", g.captcha.name, "error", err)
	}
	g.writePage(w, r, failed, client)
}

// safeRedirect returns target if it is a path on this site, and "/"
// otherwise, so that the challenge cannot redirect to another site.
func safeRedirect(target string) string {
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") || strings.HasPrefix(target, `/\`) ||
		strings.ContainsAny(target, "\r\n\t") {
		return "/"
	}
	if u, err := url.Parse(target); err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return target
}

func writeForbidden(w http.ResponseWriter, msg, eventID string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(http.StatusForbidden)+"\n"+msg+"\nEvent ID: "+eventID, http.StatusForbidden)
}

type pageData struct {
	Redirect string
	EventID  string
	// Failed shows that the last solution was rejected, with Message.
	Failed  bool
	Message string
	// Captcha shows the CAPTCHA instead of the proof of work.
	Captcha bool

	CaptchaScript string
	WidgetClass   string
	SiteKey       string
	Action        string

	Token      string
	Seed       string
	Difficulty int
	Nonce      string
	VerifyPath string
}

func (g *Guard) writePage(w http.ResponseWriter, r *http.Request, data pageData, client netip.Prefix) {
	data.Token, data.Seed = g.newChallenge(client, r.UserAgent())
	data.Difficulty = g.difficulty
	data.VerifyPath = VerifyPath
	var b [16]byte
	rand.Read(b[:])
	data.Nonce = base64.RawURLEncoding.EncodeToString(b[:])

	if data.Failed && data.Message == "" {
		data.Message = "Your network address or browser may have changed during the check."
	}
	csp := "default-src 'none'; script-src 'nonce-" + data.Nonce + "'; style-src 'unsafe-inline'; " +
		"worker-src blob:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
	if data.Captcha && g.captcha != nil {
		data.CaptchaScript = g.captcha.p.script
		data.WidgetClass = g.captcha.p.widgetClass
		data.SiteKey = g.captcha.siteKey
		if g.captcha.name == CaptchaRecaptchaV3 {
			data.Action = recaptchaAction
		}
		csp = g.captcha.csp(data.Nonce)
	} else {
		data.Captcha = false
	}

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Content-Security-Policy", csp)
	// 403, as the requested page was not served. Clients that cannot run
	// JavaScript see an error instead of an empty success.
	w.WriteHeader(http.StatusForbidden)
	if r.Method == http.MethodHead {
		return
	}
	pageTemplate.Execute(w, data)
}

var pageTemplate = template.Must(template.New("challenge").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Checking your browser</title>
<style>
:root { color-scheme: light dark; --fg: #1f2328; --muted: #59636e; --bg: #ffffff; --accent: #0969da; }
@media (prefers-color-scheme: dark) { :root { --fg: #e6edf3; --muted: #9198a1; --bg: #0d1117; --accent: #4493f8; } }
body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--fg); background: var(--bg); }
main { max-width: 32rem; padding: 2rem 1rem; text-align: center; }
h1 { font-size: 1.4rem; font-weight: 600; margin: 0 0 .5rem; }
p { margin: .5rem 0; }
.muted { color: var(--muted); font-size: .85rem; }
.spinner { width: 2rem; height: 2rem; margin: 1.5rem auto; border: 3px solid var(--muted); border-top-color: var(--accent);
  border-radius: 50%; animation: spin 1s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .spinner { animation-duration: 4s; } }
a { color: var(--accent); }
.captcha { display: flex; justify-content: center; margin: 1.5rem 0; min-height: 65px; }
</style>
</head>
<body>
<main>
{{- if .Failed}}
<h1>The browser check failed</h1>
<p>{{.Message}}</p>
<p><a href="{{.Redirect}}">Try again</a></p>
{{- else if .Captcha}}
{{- if .WidgetClass}}
<h1>Confirm that you are human</h1>
<p>Complete the check below to continue to the site.</p>
{{- else}}
<h1>Checking your browser</h1>
<div class="spinner"></div>
{{- end}}
<form id="form" method="post" action="{{.VerifyPath}}">
<input type="hidden" name="r" value="{{.Redirect}}">
<input type="hidden" name="captcha" value="">
{{- if .WidgetClass}}
<div class="captcha {{.WidgetClass}}" data-sitekey="{{.SiteKey}}" data-callback="prismwafSolved"></div>
{{- end}}
</form>
<p id="status" class="muted"></p>
<noscript><p>This site checks that it is visited with a browser. Please enable JavaScript and reload the page.</p></noscript>
<script nonce="{{.Nonce}}">
(function () {
  "use strict";
  var status = document.getElementById("status");
  document.cookie = "prismwaf_cookietest=1; path=/; SameSite=Lax";
  if (document.cookie.indexOf("prismwaf_cookietest=1") < 0) {
    status.textContent = "Please enable cookies for this site and reload the page.";
    return;
  }
  document.cookie = "prismwaf_cookietest=; path=/; max-age=0";

  // Called by the CAPTCHA with the token of a solution.
  window.prismwafSolved = function (token) {
    var form = document.getElementById("form");
    form.elements.captcha.value = token;
    form.submit();
  };
  var script = document.createElement("script");
  script.src = {{.CaptchaScript}};
  script.async = true;
  script.onerror = function () { status.textContent = "The CAPTCHA could not be loaded. Please reload the page."; };
  {{- if .Action}}
  // reCAPTCHA v3 is invisible: ask for a token as soon as it is loaded.
  script.onload = function () {
    grecaptcha.ready(function () {
      grecaptcha.execute({{.SiteKey}}, { action: {{.Action}} }).then(window.prismwafSolved);
    });
  };
  {{- end}}
  document.head.appendChild(script);
})();
</script>
{{- else}}
<h1>Checking your browser</h1>
<div class="spinner" id="spinner"></div>
<p id="status">This takes a few seconds and is only needed once.</p>
<noscript><p>This site checks that it is visited with a browser. Please enable JavaScript and reload the page.</p></noscript>
<form id="form" method="post" action="{{.VerifyPath}}" hidden>
<input type="hidden" name="c" value="{{.Token}}">
<input type="hidden" name="r" value="{{.Redirect}}">
<input type="hidden" name="n" value="">
</form>
<script nonce="{{.Nonce}}">
(function () {
  "use strict";
  var seed = {{.Seed}}, difficulty = {{.Difficulty}};
  var status = document.getElementById("status"), spinner = document.getElementById("spinner");
  function fail(msg) { status.textContent = msg; spinner.hidden = true; }

  // The clearance is a cookie: without cookies, the check would repeat
  // forever.
  document.cookie = "prismwaf_cookietest=1; path=/; SameSite=Lax";
  if (document.cookie.indexOf("prismwaf_cookietest=1") < 0) {
    fail("Please enable cookies for this site and reload the page.");
    return;
  }
  document.cookie = "prismwaf_cookietest=; path=/; max-age=0";

  // search returns the first nonce start, start+step, … for which
  // SHA-256(seed + nonce) starts with difficulty zero bits. seed + nonce
  // is shorter than 56 bytes, so the hash is a single block, and only the
  // first word of the hash is needed.
  function search(seed, difficulty, start, step) {
    var K = new Int32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
    var w = new Int32Array(64), msg = new Uint8Array(64), shift = 32 - difficulty, i;
    for (i = 0; i < seed.length; i++) msg[i] = seed.charCodeAt(i);
    for (var nonce = start; ; nonce += step) {
      var s = String(nonce), n = seed.length + s.length;
      for (i = 0; i < s.length; i++) msg[seed.length + i] = s.charCodeAt(i);
      for (i = 0; i < 16; i++) w[i] = 0;
      for (i = 0; i < n; i++) w[i >> 2] |= msg[i] << (24 - ((i & 3) << 3));
      w[n >> 2] |= 0x80 << (24 - ((n & 3) << 3));
      w[15] = n << 3;
      for (i = 16; i < 64; i++) {
        var x = w[i - 15], y = w[i - 2];
        var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      var a = 0x6a09e667, b = 0xbb67ae85 | 0, c = 0x3c6ef372, d = 0xa54ff53a | 0,
          e = 0x510e527f, f = 0x9b05688c | 0, g = 0x1f83d9ab, h = 0x5be0cd19;
      for (i = 0; i < 64; i++) {
        var t1 = (h + (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) +
          ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0;
        var t2 = ((((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) +
          ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      if ((((a + 0x6a09e667) | 0) >>> shift) === 0) return s;
    }
  }

  var done = false, workers = [];
  function submit(nonce) {
    if (done) return;
    done = true;
    workers.forEach(function (wk) { wk.terminate(); });
    var form = document.getElementById("form");
    form.elements.n.value = nonce;
    form.submit();
  }
  function solveHere() {
    if (done || solveHere.started) return;
    solveHere.started = true;
    workers.forEach(function (wk) { wk.terminate(); });
    setTimeout(function () { submit(search(seed, difficulty, 0, 1)); }, 50);
  }

  // Search in parallel in Web Workers, or in the page if they are not
  // available.
  var count = Math.min(Math.max(navigator.hardwareConcurrency || 2, 1), 8);
  try {
    var src = "var search = " + search.toString() + ";\n" +
      "onmessage = function (e) { var d = e.data; postMessage(search(d.seed, d.difficulty, d.start, d.step)); };";
    var url = URL.createObjectURL(new Blob([src], { type: "text/javascript" }));
    for (var i = 0; i < count; i++) {
      var wk = new Worker(url);
      wk.onmessage = function (e) { submit(e.data); };
      wk.onerror = solveHere;
      wk.postMessage({ seed: seed, difficulty: difficulty, start: i, step: count });
      workers.push(wk);
    }
  } catch (e) {
    solveHere();
  }
})();
</script>
{{- end}}
{{- if .EventID}}
<p class="muted">Event ID: {{.EventID}}</p>
{{- end}}
</main>
</body>
</html>
`))
