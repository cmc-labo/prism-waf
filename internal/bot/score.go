// Package bot tells browsers from bots and scrapers. Each request gets a
// bot score from its User-Agent and from headers that browsers always send;
// clients that look automated must solve a proof-of-work challenge in
// JavaScript, after which a signed cookie lets them through for a while.
//
// The score is a heuristic. It stops HTTP libraries, command-line tools,
// crawlers and naive scrapers that pretend to be browsers; scrapers that
// drive a real browser can solve the challenge, but every client they use
// has to spend CPU time on it, which makes large-scale scraping expensive.
package bot

import (
	"net/http"
	"strconv"
	"strings"
)

// Signals that add to the bot score, with their points. A score of 100
// means certainly a bot, 0 means nothing suspicious was found.
const (
	// SignalNoUserAgent: the request has no User-Agent header.
	SignalNoUserAgent = "no_user_agent"
	// SignalAutomationTool: the User-Agent is an HTTP library, command-line
	// tool, headless browser or security scanner.
	SignalAutomationTool = "automation_tool"
	// SignalCrawler: the User-Agent says it is a bot, crawler or spider.
	SignalCrawler = "crawler"
	// SignalUnknownClient: the User-Agent is not a known browser.
	SignalUnknownClient = "unknown_client"
	// SignalOutdatedBrowser: the User-Agent claims a browser version that
	// is years old, typical of scrapers with a copied User-Agent.
	SignalOutdatedBrowser = "outdated_browser"
	// The User-Agent claims a browser, but headers that the browser always
	// sends are missing.
	SignalMissingAccept         = "missing_accept"
	SignalMissingAcceptLanguage = "missing_accept_language"
	SignalMissingAcceptEncoding = "missing_accept_encoding"
	// SignalMissingFetchMetadata: no Sec-Fetch-Mode, which current
	// browsers send to every HTTPS site.
	SignalMissingFetchMetadata = "missing_fetch_metadata"
	// SignalMissingClientHints: no Sec-CH-UA, which Chromium-based
	// browsers send to every HTTPS site.
	SignalMissingClientHints = "missing_client_hints"
	// SignalHTTP10: the User-Agent claims a browser, but the request uses
	// HTTP/1.0, which browsers no longer do.
	SignalHTTP10 = "http10"
	// SignalFakeBot: the User-Agent names a bot whose identity can be
	// checked with DNS, e.g. Googlebot, but the client address does not
	// belong to it.
	SignalFakeBot = "fake_bot"
)

var signalPoints = map[string]int{
	SignalNoUserAgent:           60,
	SignalAutomationTool:        60,
	SignalCrawler:               50,
	SignalUnknownClient:         30,
	SignalOutdatedBrowser:       20,
	SignalMissingAccept:         20,
	SignalMissingAcceptLanguage: 30,
	SignalMissingAcceptEncoding: 30,
	SignalMissingFetchMetadata:  20,
	SignalMissingClientHints:    20,
	SignalHTTP10:                30,
	SignalFakeBot:               40,
}

// automationTools are lower-case User-Agent substrings of HTTP libraries,
// command-line tools and browser automation.
var automationTools = []string{
	"curl/", "wget/", "httpie/", "python-requests", "python-urllib", "python-httpx",
	"aiohttp", "scrapy", "go-http-client", "colly", "java/", "okhttp", "apache-httpclient",
	"jakarta commons-httpclient", "libwww-perl", "lwp::", "mechanize", "node-fetch",
	"axios/", "undici", "got (", "guzzlehttp", "ruby", "php/", "postmanruntime",
	"insomnia", "headlesschrome", "phantomjs", "selenium", "puppeteer", "playwright",
}

// scanners are lower-case User-Agent substrings of vulnerability and port
// scanners.
var scanners = []string{"zgrab", "masscan", "nmap", "sqlmap", "nikto", "nuclei", "wpscan", "acunetix", "openvas"}

// crawlerWords mark self-declared crawlers, e.g. "Baiduspider" or
// "facebookexternalhit". Names ending in "bot" are recognized by isCrawler.
var crawlerWords = []string{"crawl", "spider", "scrape", "slurp", "facebookexternalhit", "archiver", "fetcher"}

// Assessment is the result of Score.
type Assessment struct {
	// Score is from 0 (nothing suspicious) to 100 (certainly a bot).
	Score int
	// Signals are the reasons for the score, in a fixed order.
	Signals []string
	// Category is the kind of client that the User-Agent claims to be,
	// one of Categories.
	Category string
	// BotName is the name of a known bot, e.g. "Googlebot", or empty.
	BotName string
	// Verified reports whether the client was confirmed to be the known
	// bot with DNS. Score never sets it; Guard.Check does.
	Verified bool

	bot *knownBot
}

func (a *Assessment) add(signal string) {
	a.Signals = append(a.Signals, signal)
	a.Score = min(100, a.Score+signalPoints[signal])
}

// Score assesses how likely r was sent by a bot. secure reports whether
// the client connected with HTTPS, directly or to a trusted proxy in front
// of PrismWAF: browsers send some headers only to HTTPS sites.
func Score(r *http.Request, secure bool) Assessment {
	var a Assessment
	ua := r.Header.Get("User-Agent")
	lower := strings.ToLower(ua)
	if a.bot = findBot(lower); a.bot != nil {
		a.BotName, a.Category = a.bot.Name, a.bot.Category
		a.add(SignalCrawler)
		return a
	}
	switch {
	case strings.TrimSpace(ua) == "":
		a.Category = CategoryUnknown
		a.add(SignalNoUserAgent)
		return a
	case containsAny(lower, scanners):
		a.Category = CategoryScanner
		a.add(SignalAutomationTool)
		return a
	case containsAny(lower, automationTools):
		a.Category = CategoryAutomation
		a.add(SignalAutomationTool)
		return a
	case isCrawler(lower):
		a.Category = CategoryCrawler
		a.add(SignalCrawler)
		return a
	}
	b := parseBrowser(ua)
	if b.name == "" {
		a.Category = CategoryUnknown
		a.add(SignalUnknownClient)
		return a
	}
	a.Category = CategoryBrowser

	// The User-Agent claims a browser: check that the request looks like
	// one. Each check only applies to versions that are known to behave
	// that way, so old but real browsers are not penalized twice.
	if b.outdated() {
		a.add(SignalOutdatedBrowser)
	}
	if r.Header.Get("Accept") == "" {
		a.add(SignalMissingAccept)
	}
	if r.Header.Get("Accept-Language") == "" {
		a.add(SignalMissingAcceptLanguage)
	}
	if r.Header.Get("Accept-Encoding") == "" {
		a.add(SignalMissingAcceptEncoding)
	}
	if r.ProtoMajor == 1 && r.ProtoMinor == 0 {
		a.add(SignalHTTP10)
	}
	if secure {
		if b.sendsFetchMetadata() && r.Header.Get("Sec-Fetch-Mode") == "" {
			a.add(SignalMissingFetchMetadata)
		}
		if b.name == "chromium" && b.version >= 90 && r.Header.Get("Sec-CH-UA") == "" {
			a.add(SignalMissingClientHints)
		}
	}
	return a
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// isCrawler reports whether a lower-case User-Agent declares a crawler:
// a name ending in "bot" such as "Googlebot/2.1", "GPTBot/1.0" or
// "(like TwitterBot)", or one of crawlerWords. "bot" followed by a space
// or a letter, as in the phone model "CUBOT X30", does not count.
func isCrawler(ua string) bool {
	for s := ua; ; {
		i := strings.Index(s, "bot")
		if i < 0 {
			break
		}
		s = s[i+3:]
		if s == "" || strings.IndexByte("/-_;)+@", s[0]) >= 0 {
			return true
		}
	}
	return containsAny(ua, crawlerWords)
}

// browser is the browser engine and major version that a User-Agent
// claims.
type browser struct {
	name    string // "chromium", "firefox", "safari" or "" if none
	version int    // 0 if unknown
}

// parseBrowser recognizes the User-Agents of current browsers, which all
// start with "Mozilla/5.0".
func parseBrowser(ua string) browser {
	if !strings.HasPrefix(ua, "Mozilla/5.0 ") {
		return browser{}
	}
	switch {
	case strings.Contains(ua, "Firefox/"):
		return browser{"firefox", versionAfter(ua, "Firefox/")}
	case strings.Contains(ua, "Chrome/"):
		// Also Edge, Opera, Brave, Vivaldi and Samsung Internet.
		return browser{"chromium", versionAfter(ua, "Chrome/")}
	case strings.Contains(ua, "AppleWebKit/") && strings.Contains(ua, "Safari/"):
		// Safari and every browser on iOS (CriOS, FxiOS, …), which use
		// WebKit. Only Safari reports its version as "Version/".
		return browser{"safari", versionAfter(ua, "Version/")}
	}
	return browser{}
}

// versionAfter returns the major version number after prefix in ua, or 0.
func versionAfter(ua, prefix string) int {
	_, rest, ok := strings.Cut(ua, prefix)
	if !ok {
		return 0
	}
	end := 0
	for end < len(rest) && end < 5 && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	v, _ := strconv.Atoi(rest[:end])
	return v
}

// outdated reports versions released before 2020, which hardly any real
// user still runs.
func (b browser) outdated() bool {
	switch b.name {
	case "chromium":
		return b.version > 0 && b.version < 80
	case "firefox":
		return b.version > 0 && b.version < 72
	case "safari":
		return b.version > 0 && b.version < 13
	}
	return false
}

// sendsFetchMetadata reports whether the browser sends Sec-Fetch-* headers
// to HTTPS sites: Chrome 76, Firefox 90 and Safari 16.4 and later. For
// Safari, 17 is used to be safe.
func (b browser) sendsFetchMetadata() bool {
	switch b.name {
	case "chromium":
		return b.version >= 80
	case "firefox":
		return b.version >= 90
	case "safari":
		return b.version >= 17
	}
	return false
}
