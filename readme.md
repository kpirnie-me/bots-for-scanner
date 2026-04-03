# Bad Bot Blocker Lists

[![GitHub Issues](https://img.shields.io/github/issues/kpirnie-me/bots-for-scanner?style=for-the-badge&logo=github&color=006400&logoColor=white&labelColor=000)](https://github.com/kpirnie-me/bots-for-scanner/issues)
[![Last Commit](https://img.shields.io/github/last-commit/kpirnie-me/bots-for-scanner?style=for-the-badge&labelColor=000)](https://github.com/kpirnie-me/bots-for-scanner/commits/main)
[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg?style=for-the-badge&logo=opensourceinitiative&logoColor=white&labelColor=000)](LICENSE)


A curated collection of lists for identifying and managing malicious, unwanted, and automated web traffic. Intended for use with nginx, Apache, or any firewall/WAF that can consume plain-text blocklists.

---

## Files

### `bad-ip-addresses.list`
A list of known bad IP addresses associated with scrapers, spammers, malicious crawlers, and other unwanted traffic sources.

### `bad-referrers.list`
A list of known bad referrer domains commonly used in referrer spam, ad fraud, and SEO spam campaigns.

### `bad-user-agents.list`
A list of known bad, malicious, or unwanted user agent strings including scrapers, vulnerability scanners, download tools, spam bots, and other automated agents that should be blocked.

### `fake-googlebots.list`
A list of IP addresses that falsely identify themselves as Googlebot. These are not legitimate Google crawlers and should be blocked.

### `whitelist-ua.list`
A list of known legitimate AI bot and search engine crawler user agents. Rather than blocking these outright, this list can be used to explicitly allow them through rules that would otherwise catch them, or to apply separate rate limiting policies.

Includes crawlers from: OpenAI, Anthropic, Google, Microsoft, Perplexity, Apple, Amazon, Meta, ByteDance, DuckDuckGo, Cohere, xAI, Mistral, DeepSeek, Common Crawl, Allen Institute, Diffbot, LinkedIn, You.com, HuggingFace, Groq, Character.AI, Firecrawl, and others.

### `whitelist-ip.list`
A list of known legitimate IP ranges for trusted crawlers and services.

---

## Usage

These lists are designed to be consumed by your web server or firewall. Examples below.

### nginx

```nginx
# Block bad user agents
map $http_user_agent $bad_ua {
    default         0;
    include         /etc/nginx/lists/bad-user-agents.list;
}

# Allow known AI bots (override block rules)
map $http_user_agent $ai_bot {
    default         0;
    include         /etc/nginx/lists/whitelist-ua.list;
}

server {
    if ($bad_ua) { return 403; }
}
```

### Apache

```apache
RewriteEngine On
RewriteMap badagents txt:/etc/apache2/lists/bad-user-agents.list

RewriteCond ${badagents:%{HTTP_USER_AGENT}|0} !0
RewriteRule .* - [F,L]
```

### Cloudflare Firewall Rules (expression syntax)

```
(http.user_agent contains "AhrefsBot") or
(http.user_agent contains "SemrushBot") or
(http.user_agent contains "MJ12bot")
```

---

## Notes

- These lists are maintained manually and sourced from server logs, public blocklists, and community contributions.
- The `whitelist-ua.list` covers AI bots that identify themselves via user agent strings. Note that some AI agents (ChatGPT Atlas, OpenAI Operator, DeepSeek, and Grok in some modes) **do not use identifiable user agents** and cannot be managed via UA-based rules — IP-based rules are required for those.
- User agent strings can be spoofed. For higher-confidence bot verification, combine UA matching with IP range validation.
- The `fake-googlebots.list` complements the `bad-ip-addresses.list` specifically for IPs impersonating Googlebot.

---

## Credits

Based on and inspired by the [nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) project by Mitchell Krogza, with additional AI bot data sourced from server log analysis and public crawler documentation.
