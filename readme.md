# IIS Bad Bot Blocker

[![GitHub Issues](https://img.shields.io/github/issues/kpirnie-me/bots-for-scanner?style=for-the-badge&logo=github&color=006400&logoColor=white&labelColor=000)](https://github.com/kpirnie-me/bots-for-scanner/issues)
[![Last Commit](https://img.shields.io/github/last-commit/kpirnie-me/bots-for-scanner?style=for-the-badge&labelColor=000)](https://github.com/kpirnie-me/bots-for-scanner/commits/main)
[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg?style=for-the-badge&logo=opensourceinitiative&logoColor=white&labelColor=000)](LICENSE)

A PowerShell script that pulls live, community-maintained bad bot blocklists from GitHub, generates IIS URL Rewrite rules from them, and injects those rules directly into IIS's global configuration file — all with zero downtime risk thanks to automatic backups and a one-command rollback. It runs in minutes, can be fully automated on a daily schedule, and protects every site on the IIS instance simultaneously.

---

## How It Works

At a high level, the script does the following every time it runs:

1. **Downloads fresh blocklists** from one of two trusted upstream sources (your choice via `-WhichLists`).
2. **Downloads the whitelist** of known legitimate bots (Googlebot, Bingbot, GPTBot, ClaudeBot, etc.) from a curated, hand-maintained source.
3. **Builds a set of IIS URL Rewrite rules** from those lists — first the whitelist (so good bots are always let through), then the static security rules, then the bad bot blocks.
4. **Creates a timestamped backup** of IIS's global configuration file before touching anything.
5. **Injects the new rules** into IIS's global configuration, replacing whatever was there before.
6. **Optionally restarts IIS** to apply the changes immediately.

The rules are applied globally — meaning every website running on the IIS instance is protected by a single run of this script. No individual site configuration files are touched.

---

## The Blocklist Sources

### Option A: `Mode` — [kpirnie-me/bots-for-scanner](https://github.com/kpirnie-me/bots-for-scanner)

A curated, hand-maintained set of lists built specifically for security scanner use cases. Entries are sourced from live server log analysis, public blocklists, and ongoing community contributions. This list is smaller and more targeted than the Nginx list, making it a good choice when you want a tighter, more deliberate blocklist with less noise.

### Option B: `Nginx` — [mitchellkrogza/nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker)

This is the upstream source and the recommended default for maximum coverage. It is one of the most widely respected open-source bot-blocking projects in existence.

**Why trust it?**

- **4,600+ GitHub stars and 513 forks** — in the open source world, these numbers reflect real-world adoption and trust. Projects that don't work don't get starred by thousands of engineers.
- **Thousands of hours of programming and testing** have gone into this project. It is not a copy-paste job — it was built from scratch with deliberate testing at every step.
- The author explicitly calls out the failure mode of naive bot blocking — for example, blocking all user agents containing "Java": "it's actually one of the most dangerous BUT a lot of legitimate bots out there have 'Java' in their user agent string so the approach taken by many to block 'Java' is not only ignorant but also blocking out very legitimate crawlers including some of Google's and Bing's." This is a project maintained by someone who understands the consequences of getting it wrong.
- It blocks over 4,000 bad referrers, spam referrer domains, user-agents, bad bots, and malicious sites — and it is regularly maintained and easily updateable.
- It has been adapted for use with Nginx, Apache, and .htaccess, meaning the underlying lists are web server agnostic and have been validated across multiple platforms and deployment configurations.
- The project has been referenced in security communities, self-hosting guides, and DevOps documentation worldwide for years.
- It maintains an active issue tracker where new threats are reported and the lists are updated accordingly. The community acts as a distributed, crowd-sourced threat intelligence feed.

**The short version:** This is the industry-standard reference list for web bot blocking. Using it is the equivalent of subscribing to a well-vetted threat intelligence feed rather than writing your own from scratch.

### Whitelists — Always from [kpirnie-me/bots-for-scanner](https://github.com/kpirnie-me/bots-for-scanner)

Regardless of which block list you choose, the whitelist files are always pulled from the `kpirnie-me` repo. This is intentional. The whitelist covers the crawlers and AI agents that you absolutely do not want to block — Googlebot, Bingbot, DuckDuckBot, Apple's crawler, GPTBot (OpenAI), ClaudeBot (Anthropic), Perplexity, and dozens more.

**This is critical.** Accidentally blocking Googlebot means Google stops indexing your site. Within weeks your search rankings disappear. This script prevents that by writing whitelist rules *first*, before any block rule, with a `stopProcessing="true"` flag — meaning the moment a request matches a whitelisted bot, IIS stops evaluating rules entirely and serves the request. No block rule can override a whitelist match.

| Category | Examples |
|----------|----------|
| Major search engines | Googlebot, Bingbot, Slurp (Yahoo), Baiduspider, YandexBot, DuckDuckBot |
| AI research crawlers | GPTBot, ClaudeBot, PerplexityBot, Amazonbot, GrokBot, Cohere, Mistral, DeepSeek |
| Social & platform crawlers | FacebookBot, LinkedInBot, Applebot |
| Academic & index crawlers | AI2Bot, CommonCrawl, Diffbot, HuggingFace |

---

## What Gets Blocked and How

### Bad User-Agents

A User-Agent is a string of text that every browser, bot, and application sends along with each web request to identify itself. Legitimate tools like Chrome say something like `Mozilla/5.0 (Windows NT 10.0...) Chrome/...`. A vulnerability scanner might say `Nikto/2.1.6` or `sqlmap/1.0`.

The script downloads a list of known malicious or unwanted user agent strings, escapes them safely for use in regex patterns, chunks them into groups of 200 (to stay within IIS's rule complexity limits), and builds URL Rewrite rules that abort the connection when a match is found anywhere in the user agent string. This is a substring/contains match — it catches the bad identifier whether it appears at the start, end, or middle of the full user agent string.

Blocked categories include vulnerability scanners, content scrapers, bulk downloaders, unauthorized SEO crawlers, fake browsers, known attack tools, and bots associated with malware infrastructure.

### Bad Referrers

The HTTP Referer header tells a web server where a request is coming from. Legitimate referrers look like `https://google.com` or `https://yourotherdomain.com`. Spam referrers are domains operated by people running click-fraud, affiliate spam, SEO manipulation, and data harvesting campaigns. These requests inflate your traffic numbers, pollute your analytics, and in some cases probe for opportunities to inject content into your pages.

The script applies the same chunked regex matching approach to the `HTTP_REFERER` server variable.

### Fake Googlebots

Google's actual crawler comes from a specific set of IP addresses that Google publishes and maintains. Fake Googlebots set their user agent to `Googlebot` to try to bypass rules that whitelist it — because many admins make the mistake of allowing anything that claims to be Googlebot. This script handles that by including a separate IP-based block list of known fake Googlebot addresses, merged into the block rules alongside the user agent list.

### Static Security Rules

In addition to the fetched lists, the following hardcoded rules are written on every run. These cover common attack patterns that are always worth blocking regardless of what the upstream lists contain:

| Rule | What It Catches | Why It Matters |
|------|-----------------|----------------|
| Common Hacks 1 | Requests probing for PHP misconfigurations, `wlwmanifest` (Windows Live Writer), `web.config` exposure, and file-write exploits | Fingerprints of automated WordPress and PHP scanners |
| Common Hacks 2 | Requests for `xmlrpc`, `roundcube`, `webdav`, `w00tw00t`, `loopback`, and similar targets | Classic attack surface probes — servers that respond are flagged for follow-up attacks |
| SQL Injection – URL Path | URL paths containing SQL keywords combined with injection characters (`'`, `;`, `%22`) | Catches SQL injection attempts embedded directly in the request URL |
| SQL Injection – Query String | Same patterns but in the query string (`?id=1' OR 1=1`) | Catches the more common form where SQL injection appears in GET parameters |

---

## Backup and Recovery

Every production deployment carries risk. This script takes that seriously.

**First-run original snapshot:** The very first time the script runs on a server, it saves a copy of the current `applicationHost.config` as `applicationHost.config.original` in the backup directory. This file is **never overwritten** by subsequent runs. It represents the exact state of IIS before this tool ever touched it.

**Timestamped rolling backups:** Every run creates a backup in the format `applicationHost.config.YYYYMMDD-HHmmss.bak` before making any changes. If a run produces unexpected results, any previous state can be restored by copying the relevant `.bak` file back over the live config.

**One-command rollback to the original:** If you ever need to completely undo everything this script has ever done:

```powershell
.\Generate-IISBotBlocker.ps1 -RestoreOriginal
```

This replaces the live config with the original pre-script snapshot and exits. Run `iisreset /noforce` afterward to apply it. No data is lost, no rules are stranded, no manual XML editing required.

---

## Verifying It Works

After running the script, there are several straightforward ways to confirm it is operating correctly.

### 1. Check the Config Directly

Open `%SystemRoot%\System32\inetsrv\config\applicationHost.config` in any text editor and search for `IIS Bad Bot Blocker`. You will find the generated timestamp comment followed by all the whitelist and block rules. You can verify the whitelist entries appear before any block rules and count the total rules written.

### 2. Test With a Known Bad User-Agent

From any machine with `curl` installed (including WSL on Windows), send requests impersonating a known blocked bot and a known whitelisted bot:

```bash
# Should be silently aborted / return a connection reset
curl -A "Nikto/2.1.6" https://yoursite.com/

# Should succeed normally — Googlebot is whitelisted
curl -A "Googlebot/2.1 (+http://www.google.com/bot.html)" https://yoursite.com/
```

If the first request is dropped and the second loads normally, the rules are working exactly as intended.

### 3. Test SQL Injection Blocking

```bash
# Should be blocked — contains injection characters + SQL keyword
curl "https://yoursite.com/page?id=1%27%20OR%201%3D1"

# Should succeed — normal request
curl "https://yoursite.com/page?id=1"
```

### 4. Watch IIS Logs

IIS logs every request, including aborted ones. After running the script and restarting IIS, watch the logs (typically at `%SystemDrive%\inetpub\logs\LogFiles\`) for aborted entries. On any active internet-facing server, you will typically see blocked bot traffic appearing within hours of deployment. That is not a sign something is wrong — it is proof the blocklist is catching live traffic that was previously hitting your server unchallenged.

### 5. Compare Before and After Analytics

If you use Google Analytics or any other analytics platform, compare traffic volume and bounce rate before and after deployment. Bot traffic tends to show up as very high session counts with instant bounces and no engagement whatsoever. After blocking, these inflated numbers drop, and your real traffic data becomes more accurate and actionable.

---

## Requirements

- **IIS URL Rewrite Module 2.x** — [Download from Microsoft](https://www.iis.net/downloads/microsoft/url-rewrite). This is the only dependency. It is a free, Microsoft-published IIS extension that is widely deployed on production IIS servers.
- Windows Server 2012 / 2016 / 2019 / 2022
- PowerShell 4+
- Must be run as Administrator

---

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-WhichLists` | `string` | `Nginx` | Which block list source to use. `Nginx` for maximum coverage (recommended); `Mode` for a tighter, curated set. |
| `-ChunkSize` | `int` | `200` | How many entries to pack into each URL Rewrite rule. IIS has limits on regex complexity — 200 is a safe default that works on all tested configurations. |
| `-RestartIIS` | `switch` | off | Runs `iisreset /noforce` after writing the config, applying the new rules without dropping active connections. Recommended for automated runs. |
| `-RestoreOriginal` | `switch` | off | Restores `applicationHost.config` from the first-run `.original` snapshot and exits immediately. No rules are written. Run `iisreset /noforce` manually afterward. |
| `-BackupDir` | `string` | `C:\iis-config\backups` | Where to store backups. Created automatically if it doesn't exist. |

---

## Usage Examples

```powershell
# Standard run — Nginx lists, no auto-restart
.\Generate-IISBotBlocker.ps1

# Recommended production run — Nginx lists, restart IIS when done
.\Generate-IISBotBlocker.ps1 -RestartIIS

# Use the Mode lists instead
.\Generate-IISBotBlocker.ps1 -WhichLists Mode -RestartIIS

# Full rollback to the state before this script ever ran
.\Generate-IISBotBlocker.ps1 -RestoreOriginal

# Custom backup location
.\Generate-IISBotBlocker.ps1 -RestartIIS -BackupDir "D:\IIS-Backups"
```

---

## Automating Daily Updates

The upstream blocklists are updated regularly as new threats are identified. Running this script on a daily schedule ensures you are always protected against the latest known threats without any manual intervention.

Register with Windows Task Scheduler (run once as Administrator):

```
schtasks /create /tn "IIS Bot Blocker Update" /tr "powershell -ExecutionPolicy Bypass -NonInteractive -File C:\Scripts\Generate-IISBotBlocker.ps1 -RestartIIS" /sc daily /st 02:00 /ru SYSTEM /f
```

This schedules a daily 2:00 AM run as the SYSTEM account, which has the necessary permissions. No human involvement is required after initial setup.

---

## Rule Priority — How IIS Evaluates Them

IIS URL Rewrite evaluates rules in the order they are written in the config. This script writes them in the following deliberate order:

```
1. ✅ WHITELIST: Good bots by User-Agent   ← Evaluated first, always
2. ✅ WHITELIST: Trusted IPs               ← Evaluated second, always
3. 🚫 Static security rules               ← SQL injection, hack probes
4. 🚫 Bad User-Agent blocks (chunked)      ← Malicious / unwanted bots
5. 🚫 Bad Referrer blocks (chunked)        ← Spam referrers
```

Each whitelist rule uses `stopProcessing="true"`. This means the moment a request from Googlebot, GPTBot, or any other whitelisted agent is matched, IIS stops checking rules entirely and serves the request. It is structurally impossible for a block rule to override a whitelist match — the ordering enforces this as a guarantee, not a preference.

---

## Technical Notes

- **Regex escaping:** Every entry from the blocklists is run through `[regex]::Escape()` before being joined into alternation patterns. Special characters in bot names (dots, parentheses, slashes, etc.) cannot accidentally act as regex operators and produce incorrect matches.
- **Case insensitivity:** All matching is done with `ignoreCase="true"` as an XML attribute. The `(?i)` inline flag is not used because IIS URL Rewrite does not support it and will silently fail if present.
- **Contains matching:** User-agent and referrer patterns are unanchored — no `^` or `$`. This is deliberate. Real-world user agent strings are long and the malicious identifier may appear anywhere within them. An anchored exact match would miss the majority of real-world bot traffic.
- **Global scope:** All rules are written to `applicationHost.config`, not to individual site `web.config` files. One script run protects every site on the IIS instance simultaneously and rules cannot be bypassed by hitting a different site on the same server.
- **IP-based blocking:** This script handles bot blocking at the user-agent and referrer layer. For blocking specific IP addresses or CIDR ranges (brute force, DDoS mitigation, etc.), the appropriate tools are Windows Firewall or IIS Dynamic IP Restrictions — both operate at a lower level and are more efficient for IP-based decisions.