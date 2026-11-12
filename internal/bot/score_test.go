package bot

import (
	"net/http/httptest"
	"slices"
	"testing"
)

const (
	chromeUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	firefoxUA = "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"
	safariUA  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15"
	iosUA     = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/118.0.5993.92 Mobile/15E148 Safari/604.1"
	cubotUA   = "Mozilla/5.0 (Linux; Android 10; CUBOT X30) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"
)

// browserHeaders are the headers a browser sends on a navigation.
func browserHeaders(ua string, secure bool) map[string]string {
	h := map[string]string{
		"User-Agent":      ua,
		"Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
		"Accept-Language": "ja,en-US;q=0.9",
		"Accept-Encoding": "gzip, deflate, br",
	}
	if secure {
		h["Sec-Fetch-Mode"] = "navigate"
		if parseBrowser(ua).name == "chromium" {
			h["Sec-CH-UA"] = `"Chromium";v="130"`
		}
	}
	return h
}

func TestScore(t *testing.T) {
	without := func(h map[string]string, names ...string) map[string]string {
		for _, n := range names {
			delete(h, n)
		}
		return h
	}
	tests := []struct {
		name    string
		headers map[string]string
		secure  bool
		http10  bool
		want    int
		signals []string
	}{
		{"Chrome", browserHeaders(chromeUA, true), true, false, 0, nil},
		{"Chrome over HTTP", browserHeaders(chromeUA, false), false, false, 0, nil},
		{"Firefox", browserHeaders(firefoxUA, true), true, false, 0, nil},
		{"Safari", browserHeaders(safariUA, true), true, false, 0, nil},
		{"Chrome on iOS", without(browserHeaders(iosUA, true), "Sec-Fetch-Mode"), true, false, 0, nil},
		{"Android phone named CUBOT", browserHeaders(cubotUA, true), true, false, 0, nil},

		{"no User-Agent", map[string]string{"Accept": "*/*"}, false, false, 60, []string{SignalNoUserAgent}},
		{"curl", map[string]string{"User-Agent": "curl/8.5.0", "Accept": "*/*"}, false, false, 60, []string{SignalAutomationTool}},
		{"python-requests", map[string]string{"User-Agent": "python-requests/2.32.3"}, true, false, 60, []string{SignalAutomationTool}},
		{"headless Chrome", browserHeaders("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/130.0.0.0 Safari/537.36", true), true, false, 60, []string{SignalAutomationTool}},
		{"Googlebot", browserHeaders("Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", true), true, false, 50, []string{SignalCrawler}},
		{"GPTBot", map[string]string{"User-Agent": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"}, true, false, 50, []string{SignalCrawler}},
		{"Telegram", map[string]string{"User-Agent": "TelegramBot (like TwitterBot)"}, false, false, 50, []string{SignalCrawler}},
		{"Bytespider", map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)"}, false, false, 50, []string{SignalCrawler}},
		{"unknown client", map[string]string{"User-Agent": "MyApp/2.1 (iOS)"}, true, false, 30, []string{SignalUnknownClient}},

		{"Chrome User-Agent from a script", map[string]string{"User-Agent": chromeUA, "Accept": "*/*", "Accept-Encoding": "gzip"}, true, false, 70,
			[]string{SignalMissingAcceptLanguage, SignalMissingFetchMetadata, SignalMissingClientHints}},
		{"Chrome User-Agent only", map[string]string{"User-Agent": chromeUA}, false, false, 80,
			[]string{SignalMissingAccept, SignalMissingAcceptLanguage, SignalMissingAcceptEncoding}},
		{"Firefox without fetch metadata", without(browserHeaders(firefoxUA, true), "Sec-Fetch-Mode"), true, false, 20, []string{SignalMissingFetchMetadata}},
		{"old Chrome", browserHeaders("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36", false), false, false, 20, []string{SignalOutdatedBrowser}},
		{"HTTP/1.0", browserHeaders(chromeUA, false), false, true, 30, []string{SignalHTTP10}},
		{"capped at 100", map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0 Safari/537.36"}, true, true, 100,
			[]string{SignalOutdatedBrowser, SignalMissingAccept, SignalMissingAcceptLanguage, SignalMissingAcceptEncoding, SignalHTTP10}},
	}
	for _, tc := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		for k, v := range tc.headers {
			r.Header.Set(k, v)
		}
		if tc.http10 {
			r.ProtoMinor = 0
		}
		got := Score(r, tc.secure)
		if got.Score != tc.want || !slices.Equal(got.Signals, tc.signals) {
			t.Errorf("%s: Score = %d %v, want %d %v", tc.name, got.Score, got.Signals, tc.want, tc.signals)
		}
	}
}

func TestParseBrowser(t *testing.T) {
	for _, tc := range []struct {
		ua   string
		want browser
	}{
		{chromeUA, browser{"chromium", 130}},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0", browser{"chromium", 130}},
		{firefoxUA, browser{"firefox", 132}},
		{safariUA, browser{"safari", 18}},
		{iosUA, browser{"safari", 0}},
		{"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", browser{}},
		{"Mozilla/5.0 Chrome/99999999999", browser{"chromium", 99999}},
	} {
		if got := parseBrowser(tc.ua); got != tc.want {
			t.Errorf("parseBrowser(%q) = %v, want %v", tc.ua, got, tc.want)
		}
	}
}

func TestCategories(t *testing.T) {
	for ua, want := range map[string][2]string{
		chromeUA: {CategoryBrowser, ""},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 YaBrowser/24.10.0.0 Safari/537.36": {CategoryBrowser, ""},
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 [Pinterest/Android]":    {CategoryBrowser, ""},
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)":                                                            {CategorySearchEngine, "Googlebot"},
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)":                                                             {CategorySearchEngine, "Bingbot"},
		"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)":                                                                    {CategorySearchEngine, "YandexBot"},
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)":                              {CategoryAICrawler, "GPTBot"},
		"Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)":                                                                   {CategoryAICrawler, "ClaudeBot"},
		"CCBot/2.0 (https://commoncrawl.org/faq/)":                                                                                            {CategoryAICrawler, "CCBot"},
		"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)":                                                                  {CategorySEO, "AhrefsBot"},
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)":                                                           {CategorySocial, "facebookexternalhit"},
		"Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)":                                                                          {CategorySocial, "Slackbot"},
		"Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)":                                                              {CategoryMonitoring, "UptimeRobot"},
		"Mozilla/5.0 (compatible; ExampleBot/1.0)":                                                                                            {CategoryCrawler, ""},
		"curl/8.5.0":                             {CategoryAutomation, ""},
		"sqlmap/1.8#stable (https://sqlmap.org)": {CategoryScanner, ""},
		"MyApp/2.1":                              {CategoryUnknown, ""},
		"":                                       {CategoryUnknown, ""},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("User-Agent", ua)
		a := Score(r, false)
		if a.Category != want[0] || a.BotName != want[1] {
			t.Errorf("%q: %s %q, want %s %q", ua, a.Category, a.BotName, want[0], want[1])
		}
	}
}

func TestParseCategories(t *testing.T) {
	if got, err := ParseCategories(" AI_Crawler, seo,"); err != nil || !slices.Equal(got, []string{"ai_crawler", "seo"}) {
		t.Errorf("ParseCategories = %q, %v", got, err)
	}
	if _, err := ParseCategories("ai"); err == nil {
		t.Error("unknown category accepted")
	}
}
