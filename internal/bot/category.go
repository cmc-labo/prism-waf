package bot

import (
	"fmt"
	"strings"
)

// Categories of clients, from the User-Agent.
const (
	// CategoryBrowser: a browser, or a client that claims to be one.
	CategoryBrowser = "browser"
	// CategorySearchEngine: crawlers of search engines, e.g. Googlebot.
	CategorySearchEngine = "search_engine"
	// CategoryAICrawler: crawlers and fetchers of AI companies, e.g. GPTBot.
	CategoryAICrawler = "ai_crawler"
	// CategorySEO: crawlers of SEO and marketing tools, e.g. AhrefsBot.
	CategorySEO = "seo"
	// CategorySocial: link previews of chat apps and social networks,
	// e.g. Slackbot.
	CategorySocial = "social"
	// CategoryMonitoring: uptime monitors, e.g. UptimeRobot.
	CategoryMonitoring = "monitoring"
	// CategoryCrawler: other self-declared bots, crawlers and spiders.
	CategoryCrawler = "crawler"
	// CategoryAutomation: HTTP libraries, command-line tools and headless
	// browsers, e.g. curl.
	CategoryAutomation = "automation"
	// CategoryScanner: vulnerability and port scanners, e.g. sqlmap.
	CategoryScanner = "scanner"
	// CategoryUnknown: no User-Agent, or one that is not recognized.
	CategoryUnknown = "unknown"
)

// Categories lists every category.
var Categories = []string{
	CategoryBrowser, CategorySearchEngine, CategoryAICrawler, CategorySEO, CategorySocial,
	CategoryMonitoring, CategoryCrawler, CategoryAutomation, CategoryScanner, CategoryUnknown,
}

// ParseCategories parses a comma-separated list of categories.
func ParseCategories(s string) ([]string, error) {
	var out []string
	for _, c := range strings.Split(s, ",") {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if !isCategory(c) {
			return nil, fmt.Errorf("bot: unknown category %q: must be one of %s", c, strings.Join(Categories, ", "))
		}
		out = append(out, c)
	}
	return out, nil
}

func isCategory(c string) bool {
	for _, k := range Categories {
		if k == c {
			return true
		}
	}
	return false
}

// knownBot is a bot that is recognized by its User-Agent.
type knownBot struct {
	// Name is the name of the bot, e.g. "Googlebot".
	Name     string
	Category string
	// tokens are lower-case substrings of its User-Agents.
	tokens []string
	// domains are the domains that the reverse DNS names of the bot's
	// addresses end in. A request that claims to be the bot is verified
	// by looking up the name of its address and the addresses of that
	// name. Empty for bots that cannot be verified this way.
	domains []string
}

// Verifiable reports whether the bot's identity can be checked with DNS.
func (b *knownBot) Verifiable() bool { return len(b.domains) > 0 }

// knownBots are checked in order; the first that matches wins. Domains
// are only listed where the operator documents reverse DNS verification.
// Broad domains such as googleusercontent.com, which also names the
// virtual machines of cloud customers, must not be used.
var knownBots = []knownBot{
	// Search engines.
	{"Googlebot", CategorySearchEngine, []string{"googlebot", "google-inspectiontool", "storebot-google", "googleother", "adsbot-google", "mediapartners-google", "feedfetcher-google", "apis-google"}, []string{"googlebot.com", "google.com"}},
	{"Bingbot", CategorySearchEngine, []string{"bingbot", "bingpreview", "msnbot", "adidxbot"}, []string{"search.msn.com"}},
	{"Applebot", CategorySearchEngine, []string{"applebot"}, []string{"applebot.apple.com"}},
	{"YandexBot", CategorySearchEngine, []string{"yandex.com/bots"}, []string{"yandex.ru", "yandex.net", "yandex.com"}},
	{"Baiduspider", CategorySearchEngine, []string{"baiduspider"}, []string{"baidu.com", "baidu.jp"}},
	{"Yahoo Slurp", CategorySearchEngine, []string{"yahoo! slurp"}, []string{"crawl.yahoo.net"}},
	{"PetalBot", CategorySearchEngine, []string{"petalbot"}, []string{"petalsearch.com"}},
	{"SeznamBot", CategorySearchEngine, []string{"seznambot"}, []string{"seznam.cz"}},
	{"DuckDuckBot", CategorySearchEngine, []string{"duckduckbot", "duckassistbot"}, nil},
	{"Sogou", CategorySearchEngine, []string{"sogou"}, nil},

	// AI crawlers and fetchers.
	{"GPTBot", CategoryAICrawler, []string{"gptbot", "chatgpt-user", "oai-searchbot"}, nil},
	{"ClaudeBot", CategoryAICrawler, []string{"claudebot", "claude-user", "claude-searchbot", "anthropic-ai", "claude-web"}, nil},
	{"PerplexityBot", CategoryAICrawler, []string{"perplexitybot", "perplexity-user"}, nil},
	{"CCBot", CategoryAICrawler, []string{"ccbot"}, nil},
	{"Bytespider", CategoryAICrawler, []string{"bytespider"}, nil},
	{"Amazonbot", CategoryAICrawler, []string{"amazonbot"}, []string{"crawl.amazonbot.amazon"}},
	{"Meta AI", CategoryAICrawler, []string{"meta-externalagent", "meta-externalfetcher", "facebookbot"}, nil},
	{"cohere-ai", CategoryAICrawler, []string{"cohere-ai", "cohere-training-data-crawler"}, nil},
	{"Diffbot", CategoryAICrawler, []string{"diffbot"}, nil},
	{"YouBot", CategoryAICrawler, []string{"youbot"}, nil},
	{"Timpibot", CategoryAICrawler, []string{"timpibot"}, nil},
	{"ImagesiftBot", CategoryAICrawler, []string{"imagesiftbot"}, nil},
	{"Omgili", CategoryAICrawler, []string{"omgili"}, nil},

	// SEO tools.
	{"AhrefsBot", CategorySEO, []string{"ahrefsbot", "ahrefssiteaudit"}, nil},
	{"SemrushBot", CategorySEO, []string{"semrushbot", "siteauditbot"}, nil},
	{"MJ12bot", CategorySEO, []string{"mj12bot"}, nil},
	{"DotBot", CategorySEO, []string{"dotbot"}, nil},
	{"BLEXBot", CategorySEO, []string{"blexbot"}, nil},
	{"DataForSeoBot", CategorySEO, []string{"dataforseobot"}, nil},
	{"serpstatbot", CategorySEO, []string{"serpstatbot"}, nil},
	{"Screaming Frog", CategorySEO, []string{"screaming frog"}, nil},

	// Link previews.
	{"facebookexternalhit", CategorySocial, []string{"facebookexternalhit", "facebookcatalog"}, nil},
	{"Twitterbot", CategorySocial, []string{"twitterbot"}, nil},
	{"Slackbot", CategorySocial, []string{"slackbot", "slack-imgproxy"}, nil},
	{"Discordbot", CategorySocial, []string{"discordbot"}, nil},
	{"LinkedInBot", CategorySocial, []string{"linkedinbot"}, nil},
	{"TelegramBot", CategorySocial, []string{"telegrambot"}, nil},
	{"WhatsApp", CategorySocial, []string{"whatsapp"}, nil},
	{"Pinterestbot", CategorySocial, []string{"pinterestbot"}, nil},
	{"redditbot", CategorySocial, []string{"redditbot"}, nil},
	{"Mastodon", CategorySocial, []string{"mastodon"}, nil},

	// Uptime monitors.
	{"UptimeRobot", CategoryMonitoring, []string{"uptimerobot"}, nil},
	{"Pingdom", CategoryMonitoring, []string{"pingdom"}, nil},
	{"StatusCake", CategoryMonitoring, []string{"statuscake"}, nil},
	{"Site24x7", CategoryMonitoring, []string{"site24x7"}, nil},
	{"Better Stack", CategoryMonitoring, []string{"better uptime", "betterstack"}, nil},
	{"Uptime Kuma", CategoryMonitoring, []string{"uptime-kuma"}, nil},
	{"Datadog", CategoryMonitoring, []string{"datadog"}, nil},
}

// findBot returns the known bot that a lower-case User-Agent names, or nil.
func findBot(ua string) *knownBot {
	for i := range knownBots {
		if containsAny(ua, knownBots[i].tokens) {
			return &knownBots[i]
		}
	}
	return nil
}

// verifiedDomain reports whether a reverse DNS name belongs to one of the
// domains: it is the domain or a subdomain of it.
func verifiedDomain(name string, domains []string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, d := range domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}
