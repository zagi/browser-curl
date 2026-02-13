# Diagnostic Guide

When browser headers aren't enough, follow this flow.

## 1. Check Status Code

Run the curl command template from SKILL.md with `-o /dev/null -w '%{http_code}'` to capture the status:

| Status | Meaning | Next step |
|--------|---------|-----------|
| 200 | Check body for JS challenge (see step 2) | Step 2 |
| 403 | WAF blocked the request | Step 3 |
| 503 | Challenge page or rate limit | Step 3 |
| 000 | Connection failed | Check DNS/network |

## 2. Check for Soft Blocks

Some WAFs (Cloudflare) return 200 but serve a JS challenge page. Pipe response to `head -20` and look for: "Just a moment", "Checking your browser", "challenge-platform", "turnstile". If present — curl cannot bypass this.

## 3. Identify the WAF

Add `-D -` to capture response headers:

| Response header | WAF |
|----------------|-----|
| `cf-ray` | Cloudflare |
| `AkamaiGHost` / `x-akamai-*` | Akamai |
| `x-datadome` | DataDome |
| `x-sucuri-*` | Sucuri |
| `x-cdn: Imperva` / `incap_ses_*` | Imperva |

## 4. Fix by WAF Type

**Cloudflare**: JS challenge (most common) needs headless browser. If 403 without JS challenge, try `curl-impersonate` for TLS match.

**Akamai**: Checks HTTP/2 framing (`m:s:a:p` vs `m:a:s:p`) — only `curl-impersonate` helps.

**DataDome**: Aggressive TLS + behavioral fingerprinting — often requires a real browser.

**Generic 403**: May be IP-based blocking, geo-restriction, or `robots.txt`.

## 5. Escalation Path

1. Install `curl-impersonate`: `brew tap AaronCQL/curl-impersonate && brew install curl-impersonate`
2. If still blocked: use headless browser (Playwright/Puppeteer)
3. Check if the site has a public API that doesn't require browser fingerprinting

## Verify Headers

Use `https://httpbin.org/headers` with the curl template to confirm all Chrome 145 headers are present. Check: `Sec-Ch-Ua` contains `"Not:A-Brand"` and `"145"`, `Accept` is the full MIME list (not `*/*`).
