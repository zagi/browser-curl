# Chrome 145 Header Reference

Verified 2026-02-12. Headers must be sent in this exact order — WAFs detect incorrect ordering.

| # | Header | Value |
|---|--------|-------|
| 1 | `sec-ch-ua` | `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"` |
| 2 | `sec-ch-ua-mobile` | `?0` |
| 3 | `sec-ch-ua-platform` | `"macOS"` / `"Linux"` / `"Windows"` |
| 4 | `Upgrade-Insecure-Requests` | `1` |
| 5 | `User-Agent` | See platform table below |
| 6 | `Accept` | `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` |
| 7 | `Accept-Language` | `en-US,en;q=0.9` |
| 8 | `Accept-Encoding` | `gzip, deflate, br, zstd` |
| 9 | `Sec-Fetch-Site` | `none` |
| 10 | `Sec-Fetch-Mode` | `navigate` |
| 11 | `Sec-Fetch-User` | `?1` |
| 12 | `Sec-Fetch-Dest` | `document` |
| 13 | `Cache-Control` | `max-age=0` |
| 14 | `Priority` | `u=0, i` (HTTP/2 only) |

## Platform User-Agents

| Platform | `sec-ch-ua-platform` | User-Agent |
|----------|---------------------|------------|
| macOS | `"macOS"` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36` |
| Linux | `"Linux"` | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36` |
| Windows | `"Windows"` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36` |

## HTTP/2 + TLS (informational)

Stock curl differs from Chrome at layers that headers can't fix:
- **HTTP/2**: curl sends pseudo-headers `m:s:a:p`, Chrome sends `m:a:s:p`; SETTINGS frame values differ
- **TLS**: Chrome uses BoringSSL (unique JA3/JA4); curl uses OpenSSL/LibreSSL; `curl-impersonate` uses BoringSSL (Chrome 116 build)
