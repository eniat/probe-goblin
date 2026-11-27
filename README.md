# ProbeGoblin

Poking around where it matters.

```text
8888888b.                888              .d8888b.         888     888d8b
888   Y88b               888             d88P  Y88b        888     888Y8P
888    888               888             888    888        888     888
888   d88P888d888 .d88b. 88888b.  .d88b. 888        .d88b. 88888b. 88888888888b.
8888888P" 888P"  d88""88b888 "88bd8P  Y8b888  88888d88""88b888 "88b888888888 "88b
888       888    888  888888  88888888888888    888888  888888  888888888888  888
888       888    Y88..88P888 d88PY8b.    Y88b  d88PY88..88P888 d88P888888888  888
888       888     "Y88P" 88888P"  "Y8888  "Y8888P88 "Y88P" 88888P" 888888888  888
```

First-pass checks for authorised web application tests. Complements Burp Suite and Nessus, does not replace them.

## Install on Kali

```bash
pipx install git+https://github.com/eniat/probe-goblin
```

```bash
probegoblin setup
```

```bash
sudo apt install testssl.sh wafw00f whatweb
```

```bash
probegoblin doctor
```

- `setup` downloads Chromium for the browser stage and lists any missing system tools.
- `doctor` shows each tool, its version, Chromium, the fingerprint data dates and which API keys are set.
- whatweb is optional. Everything else missing is reported as `Not assessed` with the install command, never skipped silently.
- Kali blocks plain `pip install` into the system Python, so use pipx.
- Python 3.11 or later.

Upgrade:

```bash
pipx upgrade probegoblin
```

```bash
probegoblin update
```

## Use

```bash
probegoblin scan https://example.com
```

```bash
probegoblin scan -f targets.txt --save results.txt
```

```bash
probegoblin scan https://example.com --headers --cookies --clickjack
```

```bash
probegoblin scan https://example.com --skip waf,tls
```

```bash
probegoblin scan https://example.com --ip 192.0.2.10
```

```bash
probegoblin scan https://example.com --cookie "session=<value>" --header "X-Pentest: <value>"
```

```bash
probegoblin scan https://example.com --rate 2 --concurrency 2 --max-requests 200
```

```bash
probegoblin scan https://example.com --request-log requests.log --yes
```

### Options

- `-f, --file`: one URL per line; blank lines and `#` comments ignored; targets run one after another.
- Module flags (`--tech`, `--headers`, `--cookies`, `--clickjack`, `--cache`, `--compression`, `--cors`, `--redirects`, `--host`, `--disclosure`, `--robots`, `--api`, `--leaks`, `--javascript`, `--methods`, `--tls`, `--direct-ip`, `--waf`): run only those. No flags runs everything.
- `--skip`: comma-separated flags or names, for example `waf,tls`.
- `--ip`: connect to this IP, keep the hostname for Host and SNI. Works for an unresolvable hostname. Single target only, so not with `-f`.
- `--cookie`, `--header`: sent on every request to the target and in the browser (target host only). Masked as `<masked>` in all output.
- `--rate`, `--concurrency`, `--max-requests`: defaults 3 per second, 3, 300 per target.
- `--save <file>`: the same output as plain text. If the file exists you are asked before it is overwritten; with `--yes` a timestamped name is used instead.
- `--request-log <file>`: one line per Python request (UTC time, method, URL, status, module).
- `--yes`: no prompts. If the target keeps blocking (5 consecutive 429 or 503, or unexpected 403), the scan stops and affected modules report `Not assessed`.
- `--verbose`: also list passed checks.
- `--no-color`, `--config <file>`, `--version`.
- Ctrl+C stops requests and tools cleanly and prints what was collected; unfinished modules show `Not assessed: interrupted`. A second Ctrl+C quits immediately.

### Other commands

- `probegoblin modules`: each Goblin, its flag, what it checks and whether it can run here.
- `probegoblin doctor`: tools, Chromium, data dates, API keys.
- `probegoblin update`: refreshes the RetireJS repository, the webappanalyzer fingerprints and ProbeGoblin's data files into `~/.local/share/probegoblin`. Each file is validated before it replaces the old copy; on any failure the previous or bundled copy stays in use.
- `probegoblin setup`: downloads Chromium for Playwright.

## What it sends

- Python requests: `GET`, `HEAD` and `OPTIONS` only, enforced in the HTTP client. No forms, logins, registrations or state-changing methods.
- Same host only: the target's hostname, scheme and port. Two exceptions: one `GET http://<host>/` (RedirectGoblin) and `GET /` on each resolved IP (IPGoblin).
- Redirects to other hosts are recorded, never followed. The hostname is never changed (no `www.` added or removed).
- URLs that look like actions (logout, signout, delete, remove, unsubscribe) are never requested, and are listed at the end.
- No crawling. Roughly 40 to 170 requests per target; the pre-flight panel shows the estimate before anything is sent.
- Browser: Chromium loads the landing page and up to three login, account or password reset pages, then frame-tests them, up to 8 page loads. No clicks, typing, scrolling or form submission. Third-party resources load as they would for a visitor.
- External tools run one at a time after the HTTP modules, with time limits (testssl 15 minutes, wafw00f 2 minutes, whatweb 1 minute).
- wafw00f sends its own test requests with attack-style strings in query parameters (XSS, SQLi and path traversal patterns) to provoke a WAF. Skip it with `--skip waf` where that is not acceptable.
- testssl.sh runs with its default checks, which make many TLS handshakes.
- Lookups to other hosts: OSV, npm registry, endoflife.date, FIRST EPSS, CISA KEV, and NVD, GitHub or Snyk only when their keys are set. The target is never sent to them; only package names, versions and CVE IDs.

## Results

- `ISSUE`: configuration clearly wrong for the check.
- `MANUAL CHECK`: possible issue that was deliberately not tested. Always has manual steps.
- `OBSERVATION`: worth knowing, not a problem by itself.
- `OK`: check passed. Collapsed to a count unless `--verbose`.
- `NOT ASSESSED`: could not run, with the reason.
- Every issue and manual check has a reproduce entry that is safe to run as is (GET, HEAD or OPTIONS to the same host, supplied cookies as placeholders), or a local PoC for clickjacking.
- No severity ratings. testssl's own ratings are shown as testssl reports them.
- Secrets found in responses are shown as their first 4 characters only, for example `AKIA...(20 chars)`.

## Goblins

Requests are extra Python requests beyond the shared page store.

### TechnologyGoblin `--tech`

- Server, language, framework, CMS, JS frameworks, CDN, proxy, hosting and integrations, from the webappanalyzer fingerprints (headers, cookies, HTML, meta, script URLs and content, robots.txt, plus JS globals and DOM from the browser).
- Version and debug headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Debug-Token`, `X-Runtime`, `Server-Timing` and similar).
- Favicon mmh3 hash (Shodan format), matched against a small set of verified hashes and always printed.
- whatweb at aggression 1 as a second opinion, with redirects off.
- With `NVD_API_KEY`: CVEs for server-side versions.
- Requests: none (whatweb sends one request of its own).
- Limits:
    - Fingerprints only see what was fetched.
    - Server-side CVEs are version-based and unconfirmed; distributions backport fixes without changing the version.
    - The favicon list is small; a match identifies the favicon, not the version.
    - whatweb cannot be pinned, so it is skipped with `--ip`.

### HeaderGoblin `--headers`

- CSP (header or meta, enforced or Report-Only, multiple policies, `unsafe-inline` and its neutralisation by nonces, hashes or `strict-dynamic`, wildcards, `data:`, `blob:`, `object-src`, `base-uri`, known bypass hosts from Google CSP Evaluator).
- HSTS, X-Content-Type-Options, X-XSS-Protection (`0` or absent recommended), Referrer-Policy.
- Permissions-Policy and cross-origin headers, for information.
- Landing page and every login, account and password reset page, with differences between them.
- Requests: none.
- Limits:
    - The CSP bypass list covers common hosts, not every JSONP endpoint.
    - Pages behind authentication are only seen with `--cookie`.

### CookieGoblin `--cookies`

- Every cookie from `Set-Cookie` (including on redirects) and every cookie set by JavaScript in the browser.
- Secure, HttpOnly, SameSite, lifetime, Domain, Path, duplicates, `__Host-` and `__Secure-` rules, judged against the cookie's likely purpose (session, CSRF, analytics, preference, load balancer).
- Requests: none.
- Limits:
    - Cookies issued after login are not seen; this is always listed as a manual check.
    - Purpose is guessed from the name.
    - Chromium reports `SameSite=Lax` for cookies without the attribute, so Lax from the browser is not trusted.

### ClickjackGoblin `--clickjack`

- X-Frame-Options and CSP `frame-ancestors` on every HTML page fetched; meta and Report-Only `frame-ancestors` are ignored, as browsers ignore them.
- Browser confirmation: each browsed page is loaded in an iframe on a local page and recorded as framed, blocked or broke out.
- Any frameable page is an issue. The session cookie's SameSite value is noted, because Lax or Strict makes authenticated clickjacking unlikely.
- Gives a PoC HTML snippet to open locally.
- Requests: none (up to 4 browser loads).
- Limits:
    - Chromium blocks frame-busting navigation from cross-origin frames, so scripts that try to break out show as blocked attempts.
    - Results reflect current Chromium, not older browsers.

### CacheGoblin `--cache`

- Cache-Control, Pragma, Expires and Vary on login, account, password reset and API responses, judged by what the page contains (password form, anti-CSRF token, session cookie).
- With `--cookie`: compares the authenticated and anonymous responses for the same pages.
- Requests: up to 4 with `--cookie`, otherwise none.
- Limits:
    - Cannot see what intermediary caches actually store.

### CompressionGoblin `--compression`

- Content-Encoding on the landing and sensitive pages. Raises a BREACH manual check only when a compressed response also holds a secret token.
- Requests: none.
- Limits:
    - Does not test reflection, so BREACH is never confirmed.

### CORSGoblin `--cors`

- Probes the landing page and up to 4 API URLs with `https://probegoblin.invalid`, `null`, a prefix-match origin and a suffix-match origin (including the port when it is not the default).
- Reflected or `null` origins with credentials, wildcards, missing `Vary: Origin`, status changes.
- Requests: up to 20.
- Limits:
    - Only paths in the page store are probed.
    - Confirming data exposure needs an authenticated request, given as a manual step.

### RedirectGoblin `--redirects`

- Plain HTTP to HTTPS (permanent, same host), HTTPS to HTTP downgrades, loops, long chains, hostname canonicalisation.
- Mixed content from the HTML and from the browser's console and network log, active and passive kept apart.
- Lists redirect-style parameters (`next`, `url`, `redirect_uri`, `returnUrl` and similar) as manual checks. Never tests them.
- Requests: 1 plus same-host redirects.
- Limits:
    - HTTPS is not checked for an `http://` target, because it is outside the target given.

### HostGoblin `--host`

- `Host: probegoblin.invalid` and `X-Forwarded-Host: probegoblin.invalid` on the landing page; reflection in Location, headers, canonical tags, links, scripts or body.
- Requests: 2.
- Limits:
    - Cache poisoning and reset link poisoning are not tested; manual steps cover them.

### DisclosureGoblin `--disclosure`

- `/.git/HEAD`, `/.env`, `/.DS_Store`, server-status and server-info, phpinfo, `web.config`, cross-domain policies, backup archives, configurable in the config file.
- Tech path packs (WordPress, Drupal, Joomla, Spring Boot, Laravel, Symfony, ASP.NET, Tomcat) when the technology is detected or seen in responses.
- Content is confirmed (for example `ref:` in `.git/HEAD`, `KEY=value` lines in `.env`) and compared with three not-found baselines before anything is reported. At most 4 KB of each file is read; the heap dump is checked with HEAD only.
- Every stored response is scanned for stack traces, debug pages, internal paths, default pages and directory listings.
- Source maps confirmed with a 1 KB read; security.txt parsed against RFC 9116.
- Requests: about 15 to 30.
- Limits:
    - Fixed path lists, no brute forcing.
    - A 403 on a dotfile is only reported when the not-found baseline differs.

### RobotsGoblin `--robots`

- Interesting robots.txt and sitemap entries (admin, backup, staging, dev, internal, API, config and similar), with the status each returned. Off-host entries are listed and never requested.
- Requests: none.

### APIGoblin `--api`

- Swagger and OpenAPI documents (title, version, path and operation counts), Swagger UI, GraphiQL, API version disclosure, verbose JSON errors.
- GraphQL introspection with one GET query, never POST.
- Requests: 1.
- Limits:
    - Only the configured API paths are checked.
    - A server that rejects GET queries is reported as not assessed.

### LeakGoblin `--leaks`

- Same-host and third-party JavaScript, HTML and headers already collected: AWS keys, Google API keys, Stripe keys, Slack and GitHub tokens, private keys, JWTs, generic secret assignments, cloud storage buckets, internal hosts and private IPs, email addresses, and API endpoints for testing.
- Keys that can be public by design (Google browser keys, Stripe publishable keys) are manual checks.
- Requests: none.
- Limits:
    - Pattern matching; generic matches can be false positives.
    - Third-party JS is only scanned when the browser stage runs.

### JSGoblin `--javascript`

- Runtime: 170 libraries read from the live page by property reads only; 125 of the expressions are verified in Chromium against the real npm packages, the rest are labelled "expression not verified".
- Static: RetireJS signatures for CDN URLs, version banners, code signatures and file hashes, on same-host and third-party scripts.
- For each library: detected version and method, latest version and release date (npm), end of life (endoflife.date), CVEs with affected range, fixed version, CVSS, EPSS and CISA KEV (OSV first, then GitHub and Snyk when configured). Outdated and known vulnerability are separate statuses.
- A filename alone never gives a version: the library shows `Unknown`.
- Third-party scripts without SRI.
- Requests: none (lookups go to the intelligence sources).
- Limits:
    - A CVE is only reported when the version is inside the published affected range, but the vulnerable function may not be used.
    - Some libraries expose no version and show as present only.

### MethodsGoblin `--methods`

- `OPTIONS` to the landing page and API paths; `Allow`, `Public`, `DAV` and `Access-Control-Allow-Methods`.
- PUT, DELETE, TRACE, CONNECT, PATCH and WebDAV methods are listed as `Manual check: advertised, not tested`. They are never sent.
- nmap is not used: its http-methods script always sends POST and a random method.
- Requests: up to 5.
- Limits:
    - Advertised methods are often rejected in practice.

### TLSGoblin `--tls`

- `testssl --jsonfile <tmp> <url>` with testssl's default checks (plus `--ip` when pinned). Protocols, ciphers, forward secrecy, certificate, renegotiation, TLS compression and vulnerability checks, grouped, with testssl's own ratings.
- Requests: none from ProbeGoblin (testssl makes its own connections).
- Limits:
    - testssl tests every IP the hostname resolves to, which can take a long time behind a CDN.
    - HSTS and BREACH results are left to HeaderGoblin and CompressionGoblin.

### IPGoblin `--direct-ip`

- `GET http://<ip>/` and `GET https://<ip>/` for up to 4 resolved IPs, compared with the hostname's response.
- Requests: up to 8.
- Limits:
    - Only the resolved IPs are tried, not origin servers hidden behind a CDN.

### WAFGoblin `--waf`

- `wafw00f <url>`, runs last. Corroborated with CDN and WAF headers and cookies already seen (Cloudflare, CloudFront, Akamai, Imperva, Sucuri, Fastly, F5 and others).
- Reports "No WAF identified by wafw00f", never "no WAF".
- Requests: none from ProbeGoblin (wafw00f sends its own).
- Limits:
    - wafw00f cannot be pinned, so it is skipped with `--ip`.
    - Many WAFs are not fingerprinted.

## API keys

Environment variables only; never written to output or files.

- `NVD_API_KEY`: server-side CVE lookups in TechnologyGoblin.
- `GITHUB_TOKEN`: GitHub Advisories as an extra source for JSGoblin.
- `SNYK_TOKEN` and `SNYK_ORG_ID`: Snyk's official REST API as an extra source.
- OSV, npm, endoflife.date, EPSS and KEV need no key. Lookups are cached for 24 hours in `~/.cache/probegoblin`.
- The GitHub and Snyk clients follow the providers' published API formats but have not been tested against a live account.

## Configuration

- Defaults: `config/probegoblin.toml` in this repository. Copy it to `~/.config/probegoblin/probegoblin.toml` to change them, or pass `--config <file>`.
- Covers rate, concurrency, request cap, timeouts, size limits, JS file limit, tool time limits, User-Agent (default `ProbeGoblin/<version>`), extra headers, known paths, disclosure paths, the never-request word list and the browser page limit.
- CLI options override the file.
- `PROBEGOBLIN_CHROMIUM=/path/to/chrome` uses a specific Chromium instead of Playwright's.

## Development

```bash
pip install -e ".[dev]"
```

```bash
ruff check probegoblin tests && black --check probegoblin tests && pytest
```

```bash
python tests/verify_js_runtime.py --write
```

- New Goblins: drop a file into `probegoblin/modules/` with a `Goblin` subclass. No engine edits needed.
- `tests/verify_js_runtime.py` rechecks every runtime expression against the npm packages in Chromium and records the result in `js_runtime.yaml`.
- Browser tests are skipped when Chromium is not installed.

## Licence

GPL-3.0-or-later. Copyright (C) 2026 Taine (github.com/eniat).

- webappanalyzer fingerprints: enthec/webappanalyzer, GPL-3.0.
- RetireJS repository: RetireJS/retire.js, Apache-2.0.
- CSP bypass lists: google/csp-evaluator, Apache-2.0.
- wafw00f (BSD-3-Clause), testssl.sh (GPL-2.0) and whatweb (GPL-2.0) are run as separate programs, not bundled.
