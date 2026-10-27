#!/usr/bin/env python3
"""
CVE-2026-109618 / CVE-2026-109619 (PHP2Shell) — Passive Triage Scanner
Authorized Engagement Use Only

Purpose:
  Sweep a list of targets using ONLY passive, zero-risk HTTP requests to
  identify systems that are candidates for PHP2Shell exposure.
  No payloads. No exploitation. No behavioral probing.

  Output is a prioritized candidate list:
    CONFIRMED_VULNERABLE  — PHP version found, < fixed threshold
    CONFIRMED_PATCHED     — PHP version found, >= fixed threshold
    LIKELY_PHP            — Strong PHP signals, version not disclosed
    POSSIBLE_PHP          — Weaker signals (PHPSESSID, .php URLs, error pages)
    UNLIKELY              — No meaningful PHP indicators
    ERROR                 — Could not reach target

  Hand CONFIRMED_VULNERABLE and LIKELY_PHP to the customer for credentialed
  scanning or controlled testing in their environment.

Vulnerability background:
  CVE-2026-109618: OOM corruption — memory runs out partway through request
    setup, leaving internal data half-initialized; cleanup treats it as valid.
  CVE-2026-109619: Stale global state (use-after-free) — leftover state from
    one request points to freed memory, reachable by the next worker request.
    Session Upload Progress (enabled by default) is a confirmed trigger path.

  Both: CVSS v4.0 9.2, unauthenticated, no application interaction required.
  Affected: PHP 5.4.0 through 8.5.11 (practical scope: 8.2–8.5 with a fix).
  Fixed: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35.
  EOL (no fix): 8.1.x and below.

Signals collected (all passive):
  - PHP version in X-Powered-By or Server headers
  - PHP version disclosure paths (/phpinfo.php, etc.)
  - PHPSESSID cookie (default PHP session cookie name)
  - PHP error page patterns in 404 / probe responses
  - .php extension in URLs / Location headers
  - Common PHP app signatures (WordPress, Laravel, Drupal, etc.)
  - Session upload progress surface (presence of PHP session handling)

Usage:
  Single target:
    python3 php2shell_triage.py https://target.example.com

  Bulk from file (one URL/host per line):
    python3 php2shell_triage.py --input targets.txt --workers 10

  Output to JSON for reporting:
    python3 php2shell_triage.py --input targets.txt --json results.json

  Output to CSV:
    python3 php2shell_triage.py --input targets.txt --csv results.csv

  Filter by minimum score (version-confirmed results always pass):
    python3 php2shell_triage.py --input targets.txt --min-score 30

  Filter output to specific buckets only:
    python3 php2shell_triage.py --input targets.txt --buckets CONFIRMED_VULNERABLE,LIKELY_PHP
"""

import socket
import ssl
import sys
import re
import time
import json
import csv
import argparse
import threading
import queue
from datetime import datetime, timezone
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Fixed thresholds
# ---------------------------------------------------------------------------
FIXED_VERSIONS = {
    8: {
        2: (8, 2, 35),
        3: (8, 3, 36),
        4: (8, 4, 27),
        5: (8, 5, 12),
    }
}
# EOL: 5.x, 7.x, 8.0, 8.1 — no official fix
EOL_MAJOR_MINOR = {(5, x) for x in range(0, 7)} | \
                  {(7, x) for x in range(0, 5)} | \
                  {(8, 0), (8, 1)}

VERSION_PATHS = [
    # PHP info / version disclosure endpoints
    "/phpinfo.php", "/info.php", "/php.php", "/php_info.php",
    "/test.php", "/phptest.php", "/_test.php",
    # CMS / framework health / version paths
    "/version", "/api/version", "/api/v1/version",
    "/health", "/healthz", "/status", "/ping",
    # WordPress
    "/wp-login.php", "/wp-admin/", "/readme.html", "/license.txt",
    # Laravel / generic PHP frameworks
    "/.env",        # often returns 200 with APP_NAME etc
    "/artisan",
    # Drupal
    "/core/CHANGELOG.txt",
    # Joomla
    "/administrator/", "/joomla.xml",
    # phpMyAdmin
    "/phpmyadmin/", "/pma/", "/db/",
]

# Patterns that extract PHP version string
PHP_VERSION_PATTERNS = [
    r'[Pp][Hh][Pp]/(\d+\.\d+\.\d+)',                         # PHP/8.3.1
    r'x-powered-by:\s*[Pp][Hh][Pp]/(\d+\.\d+\.\d+)',        # X-Powered-By: PHP/8.3.1
    r'"php(?:_version)?"\s*:\s*"(\d+\.\d+\.\d+)"',           # {"php_version":"8.3.1"}
    r"PHP Version\s+(\d+\.\d+\.\d+)",                         # phpinfo() output
    r"php/(\d+\.\d+\.\d+)",                                   # php/8.3.1 (lowercase)
    r'[Pp][Hh][Pp] (\d+\.\d+\.\d+)',                         # PHP 8.3.1
    r'"runtime"\s*:\s*"[Pp][Hh][Pp].*?(\d+\.\d+\.\d+)"',
]

# Patterns indicating PHP presence without a version
PHP_PRESENCE_PATTERNS = [
    r'[Xx]-[Pp]owered-[Bb]y:\s*[Pp][Hh][Pp]',  # X-Powered-By: PHP (no version)
    r'PHPSESSID',
    r'[Ww]ord[Pp]ress',
    r'[Ll]ara[Vv]el',
    r'[Ss]ymfony',
    r'[Dd]rupal',
    r'[Jj]oomla',
    r'[Mm]agento',
    r'[Cc]ode[Ii]gniter',
    r'[Cc]ake[Pp][Hh][Pp]',
    r'[Zz]end',
    r'\.php["\'\s?#]',                           # .php URLs in page source
    r'<\?php',                                    # Raw PHP in response (misconfigured)
    r'Fatal error:.*?\.php',                      # PHP error page
    r'Parse error:.*?\.php',
    r'Warning:.*?\.php',
    r'Notice:.*?\.php',
    r'on line \d+',                               # PHP error line reference
]

# Scoring weights
SIGNAL_SCORES = {
    "php_header":           40,
    "phpsessid_cookie":     30,
    "php_app_fingerprint":  25,
    "php_error_page":       20,
    "php_url_refs":         15,
    "body_php_presence":    10,
    "interesting_paths":     5,
}

LIKELY_THRESHOLD   = 40
POSSIBLE_THRESHOLD = 10

# ---------------------------------------------------------------------------
# Colors / output
# ---------------------------------------------------------------------------
R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"
B="\033[94m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

BUCKET_DISPLAY = {
    "CONFIRMED_VULNERABLE": f"{R}{BOLD}CONFIRMED VULNERABLE{RESET}",
    "CONFIRMED_PATCHED":    f"{G}CONFIRMED PATCHED   {RESET}",
    "LIKELY_PHP":           f"{Y}LIKELY PHP          {RESET}",
    "POSSIBLE_PHP":         f"{B}POSSIBLE PHP        {RESET}",
    "UNLIKELY":             f"{DIM}UNLIKELY            {RESET}",
    "ERROR":                f"{DIM}ERROR               {RESET}",
}

BUCKET_ORDER = [
    "CONFIRMED_VULNERABLE", "CONFIRMED_PATCHED",
    "LIKELY_PHP", "POSSIBLE_PHP", "UNLIKELY", "ERROR"
]

# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _make_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

_tls_ctx = _make_context()


def http_get(host, port, use_tls, path, timeout=8, method="GET"):
    """Returns (status_code, headers_dict, body_bytes, latency_ms, error)."""
    req = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Accept: text/html,application/json,*/*\r\n"
        f"Accept-Encoding: gzip, deflate\r\n"
        f"Connection: close\r\n"
        f"User-Agent: php2shell-triage/1.0 (CVE-2026-109618 passive scan)\r\n"
        f"\r\n"
    ).encode()
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            sock = _tls_ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(req)
        buf = b""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            chunk = sock.recv(8192)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 512 * 1024:
                break
        sock.close()
        lat = int((time.monotonic() - t0) * 1000)
        sep = buf.find(b"\r\n\r\n")
        if sep == -1:
            return None, {}, buf, lat, None
        hlines = buf[:sep].decode("utf-8", errors="replace").split("\r\n")
        status_str = hlines[0]
        try:
            code = int(status_str.split()[1])
        except (IndexError, ValueError):
            code = None
        hdrs = {}
        for ln in hlines[1:]:
            if ":" in ln:
                k, _, v = ln.partition(":")
                key = k.strip().lower()
                # Accumulate set-cookie
                if key == "set-cookie":
                    hdrs[key] = hdrs.get(key, "") + " " + v.strip()
                else:
                    hdrs[key] = v.strip()
        body = buf[sep + 4:]
        return code, hdrs, body, lat, None
    except socket.timeout:
        return None, {}, b"", int((time.monotonic() - t0) * 1000), "timeout"
    except ConnectionRefusedError:
        return None, {}, b"", int((time.monotonic() - t0) * 1000), "refused"
    except Exception as e:
        return None, {}, b"", int((time.monotonic() - t0) * 1000), str(e)


def parse_version(s):
    m = re.search(r'(\d+)\.(\d+)\.(\d+)', s)
    return tuple(int(x) for x in m.groups()) if m else None


def version_verdict(vt):
    major, minor, patch = vt
    mm = (major, minor)

    # EOL lines — no fix available
    if mm in EOL_MAJOR_MINOR or major < 5:
        vs = ".".join(str(x) for x in vt)
        return "CONFIRMED_VULNERABLE", f"EOL v{vs} — no official fix"

    # Supported lines — check against threshold
    if major == 8 and minor in FIXED_VERSIONS[8]:
        fv = FIXED_VERSIONS[8][minor]
        fvs = ".".join(str(x) for x in fv)
        vs = ".".join(str(x) for x in vt)
        if vt < fv:
            return "CONFIRMED_VULNERABLE", f"v{vs} < {fvs}"
        return "CONFIRMED_PATCHED", f"v{vs} >= {fvs}"

    # Unknown minor on PHP 8 (e.g., future 8.6.x)
    vs = ".".join(str(x) for x in vt)
    return "LIKELY_PHP", f"v{vs} (unknown minor line, verify manually)"


# ---------------------------------------------------------------------------
# Signal collection
# ---------------------------------------------------------------------------

def collect_signals(host, port, use_tls, timeout):
    signals = {
        "php_version":          None,    # (major, minor, patch) tuple
        "version_source":       None,    # where the version came from
        "phpsessid_cookie":     False,   # PHPSESSID cookie present
        "php_header":           False,   # PHP in X-Powered-By or Server header
        "php_error_page":       False,   # PHP error output in response
        "php_url_refs":         False,   # .php URLs in response body
        "php_app_fingerprint":  None,    # CMS/framework name if detected
        "body_php_presence":    False,   # PHP patterns in body
        "disclosure_path":      None,    # path where version was found
        "interesting_paths":    [],      # non-404 paths from sweep
        "raw_headers_sample":   {},
        "latency_ms":           None,
        "http_status":          None,
        "error":                None,
    }

    # --- Base GET / ---
    code, hdrs, body, lat, err = http_get(host, port, use_tls, "/", timeout=timeout)
    signals["latency_ms"] = lat
    signals["http_status"] = code

    if err:
        signals["error"] = err
        return signals

    # Collect interesting headers
    for h in ("x-powered-by", "server", "set-cookie", "x-generator",
              "x-drupal-cache", "x-wordpress-cache", "x-varnish"):
        if h in hdrs:
            signals["raw_headers_sample"][h] = hdrs[h][:120]

    # PHP in X-Powered-By or Server
    xpb = hdrs.get("x-powered-by", "")
    srv = hdrs.get("server", "")
    if re.search(r'[Pp][Hh][Pp]', xpb) or re.search(r'[Pp][Hh][Pp]', srv):
        signals["php_header"] = True

    # PHP session cookie
    cookies = hdrs.get("set-cookie", "")
    if "PHPSESSID" in cookies:
        signals["phpsessid_cookie"] = True

    # PHP version from headers
    for h_val in (xpb, srv):
        for pat in PHP_VERSION_PATTERNS:
            m = re.search(pat, h_val, re.IGNORECASE)
            if m:
                v = parse_version(m.group(1))
                if v:
                    signals["php_version"] = v
                    signals["version_source"] = "GET / headers"
                    break
        if signals["php_version"]:
            break

    # Body analysis
    body_text = body[:32768].decode("utf-8", errors="replace")

    if not signals["php_version"]:
        for pat in PHP_VERSION_PATTERNS:
            m = re.search(pat, body_text, re.IGNORECASE)
            if m:
                v = parse_version(m.group(1))
                if v:
                    signals["php_version"] = v
                    signals["version_source"] = "GET / body"
                    break

    # PHP presence patterns in body
    if not signals["php_version"]:
        for pat in PHP_PRESENCE_PATTERNS:
            if re.search(pat, body_text):
                signals["body_php_presence"] = True
                break

    # .php URL references in body
    if re.search(r'href=["\'][^"\']*\.php', body_text, re.IGNORECASE):
        signals["php_url_refs"] = True

    # CMS / framework fingerprint
    cms_map = [
        ("WordPress",    r'[Ww]ord[Pp]ress'),
        ("Laravel",      r'[Ll]ara[Vv]el'),
        ("Symfony",      r'[Ss]ymfony'),
        ("Drupal",       r'[Dd]rupal'),
        ("Joomla",       r'[Jj]oomla'),
        ("Magento",      r'[Mm]agento'),
        ("CodeIgniter",  r'[Cc]ode[Ii]gniter'),
        ("CakePHP",      r'[Cc]ake[Pp][Hh][Pp]'),
    ]
    for name, pat in cms_map:
        if re.search(pat, body_text) or re.search(pat, xpb):
            signals["php_app_fingerprint"] = name
            signals["body_php_presence"] = True
            break

    # Also check x-generator header (common in Drupal, WordPress)
    gen = hdrs.get("x-generator", "")
    for name, pat in cms_map:
        if re.search(pat, gen, re.IGNORECASE):
            if not signals["php_app_fingerprint"]:
                signals["php_app_fingerprint"] = name
            signals["php_header"] = True
            break

    # --- 404 probe (PHP error pages / version) ---
    if not signals["php_version"]:
        c404, h404, b404, _, e404 = http_get(
            host, port, use_tls, "/probe-triage-xyzzy-404.php", timeout=timeout)
        if not e404 and b404:
            b404_text = b404[:16384].decode("utf-8", errors="replace")
            # PHP error output often includes version
            for pat in PHP_VERSION_PATTERNS:
                m = re.search(pat, b404_text, re.IGNORECASE)
                if m:
                    v = parse_version(m.group(1))
                    if v:
                        signals["php_version"] = v
                        signals["version_source"] = "404 PHP error page"
                        break
            if not signals["php_version"]:
                # PHP error indicators without version
                if re.search(r'(?:Fatal error|Parse error|Warning|Notice).*?\.php', b404_text):
                    signals["php_error_page"] = True
                    signals["body_php_presence"] = True
                # PHPSESSID in 404 response
                c_404 = h404.get("set-cookie", "")
                if "PHPSESSID" in c_404:
                    signals["phpsessid_cookie"] = True

    # --- Version path sweep ---
    if not signals["php_version"]:
        for vpath in VERSION_PATHS:
            vc, vh, vb, _, ve = http_get(
                host, port, use_tls, vpath,
                timeout=max(3, timeout // 2))
            if ve or vc in (404, 403, 405, None):
                continue
            # Skip HTML responses — SPA catch-all routing returns 200 text/html
            # for every path; these are not PHP endpoints and produce false positives
            if "text/html" in vh.get("content-type", ""):
                continue
            signals["interesting_paths"].append(f"{vpath} ({vc})")
            vb_text = vb[:16384].decode("utf-8", errors="replace")

            # Version extraction from sweep response
            all_vals = list(vh.values()) + [vb_text]
            for pat in PHP_VERSION_PATTERNS:
                for val in all_vals:
                    m = re.search(pat, val, re.IGNORECASE)
                    if m:
                        v = parse_version(m.group(1))
                        if v:
                            signals["php_version"] = v
                            signals["version_source"] = f"{vpath} ({vc})"
                            signals["disclosure_path"] = vpath
                            break
                if signals["php_version"]:
                    break
            if signals["php_version"]:
                break

            # PHP presence in sweep bodies
            for pat in PHP_PRESENCE_PATTERNS:
                if re.search(pat, vb_text):
                    signals["body_php_presence"] = True
                    break
            # PHPSESSID in sweep cookies
            if "PHPSESSID" in vh.get("set-cookie", ""):
                signals["phpsessid_cookie"] = True

    return signals


# ---------------------------------------------------------------------------
# Triage logic
# ---------------------------------------------------------------------------

def triage(signals):
    """
    Returns (bucket, score, reason, detail) from collected signals.

    score is an integer for scored results; None for version-confirmed results.
    Version-confirmed results bypass --min-score filtering entirely.
    """
    if signals.get("error") and signals["http_status"] is None:
        return "ERROR", None, signals["error"], {}

    php_v = signals.get("php_version")

    if php_v:
        bucket, msg = version_verdict(php_v)
        return bucket, None, msg, {
            "version_tuple":  php_v,
            "version_source": signals.get("version_source"),
        }

    # Score-based likelihood
    score = 0
    reasons = []

    if signals.get("php_header"):
        score += SIGNAL_SCORES["php_header"]
        reasons.append("PHP in X-Powered-By / Server header")
    if signals.get("phpsessid_cookie"):
        score += SIGNAL_SCORES["phpsessid_cookie"]
        reasons.append("PHPSESSID cookie (default PHP session)")
    if signals.get("php_app_fingerprint"):
        score += SIGNAL_SCORES["php_app_fingerprint"]
        reasons.append(f"{signals['php_app_fingerprint']} detected (PHP app)")
    if signals.get("php_error_page"):
        score += SIGNAL_SCORES["php_error_page"]
        reasons.append("PHP error output in response")
    if signals.get("php_url_refs"):
        score += SIGNAL_SCORES["php_url_refs"]
        reasons.append(".php URLs in response body")
    if signals.get("body_php_presence"):
        score += SIGNAL_SCORES["body_php_presence"]
        reasons.append("PHP/framework keywords in response body")
    if signals.get("interesting_paths"):
        score += SIGNAL_SCORES["interesting_paths"]
        reasons.append(
            f"Disclosure paths found: {', '.join(signals['interesting_paths'][:3])}"
        )

    if score >= LIKELY_THRESHOLD:
        return "LIKELY_PHP", score, f"score={score}", {"signals": reasons}
    if score >= POSSIBLE_THRESHOLD:
        return "POSSIBLE_PHP", score, f"score={score}", {"signals": reasons}
    return "UNLIKELY", score, "no PHP indicators", {}


# ---------------------------------------------------------------------------
# Per-target scan
# ---------------------------------------------------------------------------

def scan_target(raw_target, timeout=8):
    target = raw_target.strip()
    if not target or target.startswith("#"):
        return None

    if not target.startswith("http"):
        target_url = "https://" + target
    else:
        target_url = target

    parsed = urlparse(target_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = (parsed.scheme == "https")

    result = {
        "target":     raw_target.strip(),
        "host":       host,
        "port":       port,
        "tls":        use_tls,
        "bucket":     None,
        "score":      None,
        "reason":     None,
        "detail":     {},
        "signals":    {},
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        signals = collect_signals(host, port, use_tls, timeout)

        # HTTPS fail → retry HTTP
        if signals.get("error") in ("refused", "timeout") and use_tls:
            port_h = parsed.port or 80
            signals_h = collect_signals(host, port_h, False, timeout)
            if not signals_h.get("error"):
                signals = signals_h
                result["port"] = port_h
                result["tls"] = False

        result["signals"] = signals
        bucket, score, reason, detail = triage(signals)
        result["bucket"] = bucket
        result["score"] = score
        result["reason"] = reason
        result["detail"] = detail

    except Exception as e:
        result["bucket"] = "ERROR"
        result["score"] = None
        result["reason"] = str(e)

    return result


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def tag(level):
    return {"info": f"{C}[*]{RESET}", "ok": f"{G}[+]{RESET}",
            "warn": f"{Y}[!]{RESET}", "fail": f"{R}[-]{RESET}"}.get(level, "[?]")


def print_result(r, verbose=False):
    if not r:
        return
    bucket = r["bucket"]
    display = BUCKET_DISPLAY.get(bucket, bucket)
    lat = r["signals"].get("latency_ms")
    lat_str = f"  {DIM}{lat}ms{RESET}" if lat else ""
    score = r.get("score")
    score_str = f"  {DIM}score={score}{RESET}" if score is not None else ""
    print(f"  {display}  {r['target']}{lat_str}{score_str}")
    print(f"             {DIM}{r['reason']}{RESET}")

    if verbose:
        detail = r.get("detail", {})
        if "version_tuple" in detail:
            vt = detail["version_tuple"]
            vs = ".".join(str(x) for x in vt)
            print(f"             {DIM}version: v{vs}  source: {detail.get('version_source', '?')}{RESET}")
        if "signals" in detail:
            for s in detail["signals"]:
                print(f"             {DIM}signal: {s}{RESET}")
        sigs = r.get("signals", {})
        if sigs.get("php_app_fingerprint"):
            print(f"             {DIM}app: {sigs['php_app_fingerprint']}{RESET}")
        if sigs.get("interesting_paths"):
            for p in sigs["interesting_paths"][:5]:
                print(f"             {DIM}path: {p}{RESET}")
        if sigs.get("raw_headers_sample"):
            for k, v in list(sigs["raw_headers_sample"].items())[:4]:
                print(f"             {DIM}{k}: {v}{RESET}")


def write_json(results, path):
    clean = []
    for r in results:
        if not r:
            continue
        rc = dict(r)
        if "php_version" in rc.get("signals", {}):
            v = rc["signals"]["php_version"]
            if isinstance(v, tuple):
                rc["signals"]["php_version"] = list(v)
        if "version_tuple" in rc.get("detail", {}):
            v = rc["detail"]["version_tuple"]
            if isinstance(v, tuple):
                rc["detail"]["version_tuple"] = list(v)
        clean.append(rc)
    with open(path, "w") as f:
        json.dump(clean, f, indent=2, default=str)
    print(f"\n{tag('ok')} JSON written: {path}")


def write_csv(results, path):
    rows = []
    for r in results:
        if not r:
            continue
        sigs = r.get("signals", {})
        vt = sigs.get("php_version")
        rows.append({
            "target":              r["target"],
            "bucket":              r["bucket"],
            "score":               r.get("score", ""),
            "reason":              r["reason"],
            "php_version":         ".".join(str(x) for x in vt) if vt else "",
            "version_source":      sigs.get("version_source", ""),
            "php_app_fingerprint": sigs.get("php_app_fingerprint", ""),
            "phpsessid_cookie":    sigs.get("phpsessid_cookie", False),
            "php_header":          sigs.get("php_header", False),
            "php_error_page":      sigs.get("php_error_page", False),
            "latency_ms":          sigs.get("latency_ms", ""),
            "http_status":         sigs.get("http_status", ""),
            "interesting_paths":   " | ".join(sigs.get("interesting_paths", [])),
            "error":               sigs.get("error", ""),
            "scanned_at":          r.get("scanned_at", ""),
        })
    if not rows:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"{tag('ok')} CSV written: {path}")


# ---------------------------------------------------------------------------
# Filtering helpers
# ---------------------------------------------------------------------------

def passes_filters(result, min_score, bucket_filter):
    """
    Returns True if a result should be included in output.

    Rules:
      - Version-confirmed buckets always pass min_score (score=None means bypass).
      - Scored buckets must have score >= min_score.
      - bucket_filter is the final gate if set.
    """
    if not result:
        return False

    bucket = result.get("bucket")
    score = result.get("score")
    version_confirmed = bucket in ("CONFIRMED_VULNERABLE", "CONFIRMED_PATCHED")

    if min_score is not None and not version_confirmed:
        if score is None or score < min_score:
            return False

    if bucket_filter and bucket not in bucket_filter:
        return False

    return True


# ---------------------------------------------------------------------------
# Worker pool
# ---------------------------------------------------------------------------

def worker(q, results, lock, timeout, verbose, min_score, bucket_filter):
    while True:
        item = q.get()
        if item is None:
            q.task_done()
            break
        try:
            r = scan_target(item, timeout=timeout)
            with lock:
                results.append(r)
                if passes_filters(r, min_score, bucket_filter):
                    print_result(r, verbose=verbose)
        finally:
            q.task_done()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-109618/109619 (PHP2Shell) passive triage scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Output buckets:
  CONFIRMED VULNERABLE  — PHP version found, below fixed threshold
  CONFIRMED PATCHED     — PHP version found, at or above fixed threshold
  LIKELY PHP            — Strong PHP signals, version not disclosed     (score >= 40)
  POSSIBLE PHP          — Weaker signals (PHPSESSID, .php refs, etc.)  (score >= 10)
  UNLIKELY              — No PHP indicators detected                     (score < 10)

Scoring (scored path only — version-confirmed skips scoring):
  PHP in X-Powered-By / Server header     +40
  PHPSESSID cookie                        +30
  CMS/framework fingerprint               +25
  PHP error output in response            +20
  .php URLs in response body              +15
  PHP/framework keywords in body          +10
  Interesting disclosure paths            +5

Instrumentation switches:
  --min-score N           Only report scored results with score >= N.
                          Version-confirmed results always pass regardless of N.
  --buckets B[,B,...]     Only output results matching these bucket names.
                          Example: --buckets CONFIRMED_VULNERABLE,LIKELY_PHP

Recommended workflow:
  1. Run triage across all customer-scoped targets
  2. Deliver CONFIRMED VULNERABLE and LIKELY PHP lists to customer
  3. Customer runs credentialed Nessus scan (plugin 369483) on those hosts
  4. POSSIBLE PHP hosts: low priority, confirm with customer if they run PHP

Examples:
  python3 php2shell_triage.py https://target.example.com
  python3 php2shell_triage.py --input targets.txt --workers 10 --json results.json
  python3 php2shell_triage.py --input targets.txt --csv results.csv --verbose
  python3 php2shell_triage.py --input targets.txt --min-score 30
  python3 php2shell_triage.py --input targets.txt --buckets CONFIRMED_VULNERABLE,LIKELY_PHP
        """
    )
    parser.add_argument("target", nargs="?",
                        help="Single target URL or host:port")
    parser.add_argument("--input", "-i", metavar="FILE",
                        help="File with one target per line (URLs or host:port)")
    parser.add_argument("--workers", "-w", type=int, default=5,
                        help="Concurrent scan threads for bulk mode (default: 5)")
    parser.add_argument("--timeout", type=int, default=8,
                        help="Per-request timeout in seconds (default: 8)")
    parser.add_argument("--json", metavar="FILE",
                        help="Write full results to JSON file")
    parser.add_argument("--csv", metavar="FILE",
                        help="Write results to CSV file")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show signal details per target")
    parser.add_argument("--min-score", type=int, default=None, metavar="N",
                        help="Only report scored results with score >= N. "
                             "Version-confirmed results always pass. (default: no filter)")
    parser.add_argument("--buckets", default=None, metavar="BUCKET[,BUCKET,...]",
                        help="Comma-separated list of bucket names to include in output. "
                             "Example: --buckets CONFIRMED_VULNERABLE,LIKELY_PHP")
    args = parser.parse_args()

    if not args.target and not args.input:
        parser.print_help()
        sys.exit(1)

    # Parse bucket filter
    bucket_filter = None
    if args.buckets:
        bucket_filter = set(b.strip().upper() for b in args.buckets.split(","))
        valid = set(BUCKET_ORDER)
        unknown = bucket_filter - valid
        if unknown:
            print(f"{tag('warn')} Unknown bucket name(s): {', '.join(unknown)}")
            print(f"         Valid buckets: {', '.join(BUCKET_ORDER)}")

    targets = []
    if args.target:
        targets.append(args.target)
    if args.input:
        with open(args.input) as f:
            targets.extend(
                ln.strip() for ln in f
                if ln.strip() and not ln.startswith("#")
            )

    print("=" * 68)
    print("  CVE-2026-109618/109619 (PHP2Shell) Passive Triage")
    print("=" * 68)
    print(f"  Targets  : {len(targets)}")
    print(f"  Workers  : {min(args.workers, len(targets))}")
    print(f"  Timeout  : {args.timeout}s per request")
    print(f"  Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Mode     : PASSIVE ONLY — no payloads, no session manipulation")
    if args.min_score is not None:
        print(f"  Min score: {args.min_score} (version-confirmed always passes)")
    if bucket_filter:
        print(f"  Buckets  : {', '.join(sorted(bucket_filter))}")
    print("=" * 68 + "\n")

    results = []
    lock = threading.Lock()

    if len(targets) == 1:
        r = scan_target(targets[0], timeout=args.timeout)
        results.append(r)
        if passes_filters(r, args.min_score, bucket_filter):
            print_result(r, verbose=True)
    else:
        q = queue.Queue()
        threads = []
        n_workers = min(args.workers, len(targets))
        for _ in range(n_workers):
            t = threading.Thread(
                target=worker,
                args=(q, results, lock, args.timeout, args.verbose,
                      args.min_score, bucket_filter),
                daemon=True,
            )
            t.start()
            threads.append(t)
        for tgt in targets:
            q.put(tgt)
        for _ in range(n_workers):
            q.put(None)
        q.join()

    # Summary
    results = [r for r in results if r]
    all_buckets = {}
    for r in results:
        b = r.get("bucket", "ERROR")
        all_buckets[b] = all_buckets.get(b, []) + [r["target"]]

    filtered = [r for r in results if passes_filters(r, args.min_score, bucket_filter)]
    filtered_buckets = {}
    for r in filtered:
        b = r.get("bucket", "ERROR")
        filtered_buckets[b] = filtered_buckets.get(b, []) + [r["target"]]

    print(f"\n{'=' * 68}")
    print(f"  {BOLD}SUMMARY{RESET}  ({len(results)} scanned, {len(filtered)} shown)")
    print(f"{'=' * 68}")
    for b in BUCKET_ORDER:
        all_count = len(all_buckets.get(b, []))
        shown_count = len(filtered_buckets.get(b, []))
        if not all_count:
            continue
        diff = f"  {DIM}({shown_count} shown){RESET}" if shown_count != all_count else ""
        print(f"  {BUCKET_DISPLAY.get(b, b)} : {all_count}{diff}")

    for_customer = (filtered_buckets.get("CONFIRMED_VULNERABLE", []) +
                    filtered_buckets.get("LIKELY_PHP", []))
    if for_customer:
        print(f"\n  {BOLD}Recommend for credentialed scan / customer testing:{RESET}")
        for t in for_customer:
            print(f"    {Y}→{RESET} {t}")

    possible = filtered_buckets.get("POSSIBLE_PHP", [])
    if possible:
        print(f"\n  {BOLD}Lower priority — confirm stack with customer:{RESET}")
        for t in possible[:10]:
            print(f"    {B}→{RESET} {t}")
        if len(possible) > 10:
            print(f"    {DIM}... and {len(possible) - 10} more{RESET}")

    print(f"\n  Fix : PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35")
    print(f"  Nessus : Plugin 369483 (local+remote) | WAS 115719-115722")
    print(f"  Ref : https://www.tenable.com/cve/CVE-2026-109618\n")

    if args.json:
        write_json(results, args.json)
    if args.csv:
        write_csv(results, args.csv)

    if all_buckets.get("CONFIRMED_VULNERABLE"):
        sys.exit(2)
    if all_buckets.get("LIKELY_PHP"):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
