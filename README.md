# PHP2Shell — CVE-2026-109618 / CVE-2026-109619 Detection Tooling

Authorized Engagement Use Only

Passive triage tooling for CVE-2026-109618 and CVE-2026-109619 — critical unauthenticated RCE in PHP via OOM corruption and stale global state.

---

## Vulnerability Overview

| | |
|---|---|
| **CVEs** | CVE-2026-109618, CVE-2026-109619 |
| **CVSS v4.0** | 9.2 (both) |
| **Class** | OOM corruption + use-after-free via fatal error / longjmp handling |
| **Attack surface** | Every PHP web-serving mode: PHP-FPM, mod_php, php-cgi, FrankenPHP, LiteSpeed |
| **Trigger (109619)** | Session Upload Progress (enabled by default); also other paths |
| **Impact** | Unauthenticated RCE before any application code runs (mod_php worst case) |
| **Exploitation** | Actively exploited in the wild; public PoCs circulating as of Oct 2026 |
| **Affected** | PHP 5.4.0 through 8.5.11; EOL lines 8.1.x and below have no official fix |

### Fixed versions

| Release line | Fixed at |
|---|---|
| PHP 8.5.x | 8.5.12 |
| PHP 8.4.x | 8.4.27 |
| PHP 8.3.x | 8.3.36 |
| PHP 8.2.x | 8.2.35 |
| PHP 7.4.x – 8.1.x | No official release; minimal source backports only |
| PHP ≤ 7.3.x | End-of-life; no fix |

**Interim mitigations (not a complete fix):**
- CVE-2026-109618: `memory_limit=-1` (must not be overridable by application)
- CVE-2026-109619: `session.upload_progress.enabled=0`; on PHP 8.5 also `fatal_error_backtraces=0`
- Restart all PHP workers after any ini change

**Nessus coverage:** Plugin 369483 (local + remote checks); WAS plugins 115719–115722 (unauthenticated version checks for PHP 8.2–8.5)

---

## Tools

### `php2shell_triage.py` — Passive Triage Scanner

Zero-risk passive sweep for CVE-2026-109618 / CVE-2026-109619. No payloads. No session manipulation.

**Signals collected (all passive):**
- PHP version in `X-Powered-By` / `Server` headers
- `PHPSESSID` cookie (default PHP session cookie — Session Upload Progress surface)
- PHP error page output in 404 / probe responses
- `.php` URL references in response body
- CMS/framework fingerprints (WordPress, Laravel, Drupal, Joomla, Symfony, Magento, CodeIgniter, CakePHP)
- Version disclosure from `/phpinfo.php`, `/info.php`, WP `/readme.html`, Laravel `.env`, and 20+ paths

**Output buckets:**

| Bucket | Meaning |
|---|---|
| `CONFIRMED_VULNERABLE` | PHP version disclosed, below fix threshold |
| `CONFIRMED_PATCHED` | PHP version disclosed, at or above fix threshold |
| `LIKELY_PHP` | Strong PHP signals, version not disclosed |
| `POSSIBLE_PHP` | Weaker signals — PHPSESSID, `.php` refs, CMS patterns |
| `UNLIKELY` | No PHP indicators |

**Scoring (scored path only — version-confirmed skips scoring):**

| Signal | Points |
|---|---|
| PHP in `X-Powered-By` / `Server` header | +40 |
| `PHPSESSID` cookie | +30 |
| CMS / framework fingerprint | +25 |
| PHP error output in response | +20 |
| `.php` URLs in response body | +15 |
| PHP / framework keywords in body | +10 |
| Interesting disclosure paths | +5 |

Thresholds: `LIKELY_PHP` ≥ 40 · `POSSIBLE_PHP` ≥ 10

A note on `PHPSESSID`: the cookie alone (30 pts) puts a target in `POSSIBLE_PHP`, not `LIKELY_PHP`. It takes a PHP header *or* a CMS fingerprint on top of that to reach the `LIKELY_PHP` threshold (40 pts). Nearly all default PHP installs expose PHPSESSID, so `POSSIBLE_PHP` is a broad net; `LIKELY_PHP` is the high-confidence tier.

**Exit codes:** `2` = confirmed vulnerable · `1` = likely candidates · `0` = clean (CI integration)

**Usage:**

```bash
# Single target
python3 php2shell_triage.py https://target.example.com

# Bulk from file
python3 php2shell_triage.py --input targets.txt --workers 10

# Output to JSON + CSV for reporting
python3 php2shell_triage.py --input targets.txt --json results.json --csv results.csv

# Verbose — show all signals per target
python3 php2shell_triage.py --input targets.txt --verbose

# Only show results scoring 30+ (version-confirmed always passes through)
python3 php2shell_triage.py --input targets.txt --min-score 30

# Only output confirmed vulnerable and likely candidates
python3 php2shell_triage.py --input targets.txt --buckets CONFIRMED_VULNERABLE,LIKELY_PHP
```

---

## Instrumentation switches

### `--min-score N`

Filter console output to scored results with `score >= N`. Version-confirmed results (`CONFIRMED_VULNERABLE` / `CONFIRMED_PATCHED`) always pass regardless of `N` — they have no score and should never be suppressed.

JSON and CSV output always contains all results regardless of this flag.

```bash
# Cut the noise — suppress POSSIBLE_PHP results scoring < 25
python3 php2shell_triage.py --input targets.txt --min-score 25
```

### `--buckets BUCKET[,BUCKET,...]`

Restrict console output to the named bucket(s). Valid names: `CONFIRMED_VULNERABLE`, `CONFIRMED_PATCHED`, `LIKELY_PHP`, `POSSIBLE_PHP`, `UNLIKELY`, `ERROR`.

```bash
# Hot targets only — skip everything below LIKELY_PHP
python3 php2shell_triage.py --input targets.txt --buckets CONFIRMED_VULNERABLE,LIKELY_PHP

# Combine with min-score for a tight feed
python3 php2shell_triage.py --input targets.txt --buckets LIKELY_PHP,POSSIBLE_PHP --min-score 20
```

The `--min-score` and `--buckets` flags control what is shown on the console. JSON / CSV always capture everything. Exit codes are based on all results.

---

## Recommended workflow

```
1. Run php2shell_triage.py across all customer-scoped targets
2. Deliver CONFIRMED_VULNERABLE and LIKELY_PHP lists to customer
3. Customer runs credentialed Nessus scan (plugin 369483) on those hosts
4. POSSIBLE_PHP hosts: confirm PHP stack with customer, then escalate or deprioritize
5. Document findings; reference CVE-2026-109618 and CVE-2026-109619 in report
```

---

## Requirements

Python 3.8+, stdlib only — no external dependencies.

```bash
python3 php2shell_triage.py --help
```

---

## References

- [Tenable FAQ — CVE-2026-109618 / CVE-2026-109619](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
- [Unit 42 Threat Brief](https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/)
- [watchTowr Intelligence](https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/)
- [CISA Alert — Critical Vulnerabilities in PHP](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)
- PHP advisories: [GHSA-w8hw-w9fx-j79w](https://github.com/advisories/GHSA-w8hw-w9fx-j79w) (CVE-2026-109618) | [GHSA-6wmf-4rv5-p3rp](https://github.com/advisories/GHSA-6wmf-4rv5-p3rp) (CVE-2026-109619)

---

## License & Use

These tools are intended for use in authorized penetration testing engagements. Use only against systems you own or have explicit written authorization to test.
