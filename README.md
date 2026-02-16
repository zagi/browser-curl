# browser-curl

A Claude Code skill that wraps `curl` with Chrome 145 browser headers to bypass WAF (Web Application Firewall) header fingerprinting.

## The Problem

In 2026, a plain `curl` request gets blocked by most WAF-protected sites:

```bash
$ curl -sS -o /dev/null -w '%{http_code}' https://nowsecure.nl
403
```

WAFs detect non-browser clients through three layers:

1. **HTTP Headers** — stock curl sends no `Sec-CH-UA`, no `Sec-Fetch-*`, no Client Hints
2. **HTTP/2 Fingerprint** — curl sends pseudo-headers in `m:s:a:p` order vs Chrome's `m:a:s:p`
3. **TLS Fingerprint (JA3/JA4)** — curl uses OpenSSL/LibreSSL, not Chrome's BoringSSL

## What This Skill Does

**Fully bypasses Layer 1** by injecting all Chrome 145 headers in the correct order, including the GREASE brand rotation, Client Hints, and Sec-Fetch metadata.

**Partially addresses Layer 2** by using `--http2` when available.

**Does not bypass Layer 3** unless `curl-impersonate` is installed (auto-detected).

| | Stock curl | browser-curl | curl-impersonate |
|---|---|---|---|
| Headers | curl default | Chrome 145 exact | Chrome 116 |
| HTTP/2 order | m:s:a:p | m:s:a:p (curl limitation) | m:a:s:p |
| TLS/JA4 | LibreSSL/OpenSSL | LibreSSL/OpenSSL | BoringSSL (Chrome match) |
| WAF bypass rate | ~20% | ~70% | ~95% |

## Installation

### As a Claude Code skill

```bash
mkdir -p ~/.agents/skills
ln -s /path/to/browser-curl ~/.agents/skills/browser-curl
```

### Standalone usage

```bash
git clone https://github.com/zagi/browser-curl.git
bash browser-curl/browser_curl.sh https://example.com
```

## Usage

```bash
# Basic GET
bash browser_curl.sh https://example.com

# POST JSON data
bash browser_curl.sh -X POST \
  -H "Content-Type: application/json" \
  -d '{"query": "test"}' \
  https://api.example.com/endpoint

# Diagnose why a request is failing
bash browser_curl.sh --diagnose https://example.com

# Use a different Chrome version
bash browser_curl.sh --chrome-version 146 https://example.com

# Disable cookie persistence
bash browser_curl.sh --no-cookies https://example.com
```

### Windows / PowerShell

```powershell
.\browser_curl.ps1 https://example.com
.\browser_curl.ps1 -Diagnose https://example.com
```

Requires `curl.exe` on PATH (not PowerShell's `curl` alias).

## Diagnostic Mode

When a request fails, use `--diagnose` to find out why:

1. Makes the request and captures the HTTP status
2. Identifies the WAF (Cloudflare, Akamai, DataDome, Sucuri, Imperva)
3. Verifies Chrome 145 headers are sent correctly via httpbin.org
4. Reports TLS fingerprint status and curl-impersonate availability

## Capability Detection

The script auto-detects the runtime environment:

- **Platform** — sets User-Agent and `sec-ch-ua-platform` for macOS/Windows/Linux
- **HTTP/2** — uses `--http2` if nghttp2 is linked
- **Brotli/Zstd** — only advertises in `Accept-Encoding` if curl can decompress
- **curl-impersonate** — uses it automatically for full TLS fingerprint matching

## Limitations

- **JavaScript challenges** require a real browser (Playwright/Puppeteer)
- **TLS fingerprint** differs without `curl-impersonate`
- **HTTP/2 framing** differs from Chrome at the frame level
- **GREASE brand** defaults to Chrome 145 — use `--chrome-version N` to switch

## System Requirements

- **curl** 7.68+ (for `--http2`)
- **jq** (optional, for JSON processing)
- **curl-impersonate** (optional, for TLS fingerprint matching)

## License

[MIT](LICENSE)
