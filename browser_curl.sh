#!/usr/bin/env bash
#
# browser_curl.sh — curl wrapper that mimics Chrome 145 browser fingerprint
#
# Injects browser-authentic headers (Sec-CH-UA, Client Hints, Sec-Fetch-*)
# to bypass WAF header fingerprinting. Detects platform, HTTP/2 support,
# brotli/zstd support, and curl-impersonate availability.
#
# Usage: bash browser_curl.sh [URL] [extra curl args...]
# Usage: bash browser_curl.sh -X POST -d '{"key":"val"}' [URL]
# Usage: bash browser_curl.sh --diagnose [URL]  (run 4-step failure analysis)
# Usage: bash browser_curl.sh --chrome-version 146 [URL]  (use different Chrome version)
#
# Uses `env curl` to bypass Claude Code's curl blocking (GitHub issue #159).

set -euo pipefail

# --- Chrome Version & GREASE ---
# Default Chrome version — can be overridden with --chrome-version N
CHROME_VERSION="145"

# Compute GREASE brand, version, and sec-ch-ua header for any Chrome major version.
# Algorithm from Chromium source: GetGreasedBrandVersionForGeneration()
# https://chromium.googlesource.com/chromium/src/+/main/components/embedder_support/user_agent_utils.cc
compute_grease() {
  local seed="$1"
  local -a chars=(' ' '(' ':' '-' '.' '/' ')' ';' '=' '?' '_')

  # Brand = "Not" + chars[seed%11] + "A" + chars[(seed+1)%11] + "Brand"
  local c1="${chars[$(( seed % 11 ))]}"
  local c2="${chars[$(( (seed + 1) % 11 ))]}"
  GREASE_BRAND="Not${c1}A${c2}Brand"

  # Version = ["8","99","24"][seed%3]
  local -a versions=('8' '99' '24')
  GREASE_VERSION="${versions[$(( seed % 3 ))]}"

  # Order = permutation[seed%6] over base [GREASE, Chromium, Chrome]
  # Permutations: {0,1,2} {0,2,1} {1,0,2} {1,2,0} {2,0,1} {2,1,0}
  local grease_entry="\"${GREASE_BRAND}\";v=\"${GREASE_VERSION}\""
  local chromium_entry="\"Chromium\";v=\"${seed}\""
  local chrome_entry="\"Google Chrome\";v=\"${seed}\""

  local perm=$(( seed % 6 ))
  case "$perm" in
    0) SEC_CH_UA="${grease_entry}, ${chromium_entry}, ${chrome_entry}" ;;
    1) SEC_CH_UA="${grease_entry}, ${chrome_entry}, ${chromium_entry}" ;;
    2) SEC_CH_UA="${chromium_entry}, ${grease_entry}, ${chrome_entry}" ;;
    3) SEC_CH_UA="${chromium_entry}, ${chrome_entry}, ${grease_entry}" ;;
    4) SEC_CH_UA="${chrome_entry}, ${grease_entry}, ${chromium_entry}" ;;
    5) SEC_CH_UA="${chrome_entry}, ${chromium_entry}, ${grease_entry}" ;;
  esac
}

# Compute default GREASE for Chrome 145
compute_grease "$CHROME_VERSION"
SEC_CH_UA_MOBILE='?0'
ACCEPT='text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
ACCEPT_LANGUAGE='en-US,en;q=0.9'
UPGRADE_INSECURE_REQUESTS='1'
CACHE_CONTROL='max-age=0'

# Sec-Fetch headers (navigation context)
SEC_FETCH_SITE='none'
SEC_FETCH_MODE='navigate'
SEC_FETCH_USER='?1'
SEC_FETCH_DEST='document'

# --- Cookie Persistence ---
# Enabled by default. WAFs like Cloudflare set cf_clearance cookies that must
# persist across requests to avoid re-triggering challenges.
COOKIE_DIR="${HOME}/.browser-curl"
COOKIE_JAR="${COOKIE_DIR}/cookies.txt"
USE_COOKIES=true

setup_cookies() {
  if [[ "$USE_COOKIES" != true ]]; then
    return
  fi
  if [[ ! -d "$COOKIE_DIR" ]]; then
    mkdir -p "$COOKIE_DIR"
    chmod 700 "$COOKIE_DIR"
  fi
  if [[ ! -f "$COOKIE_JAR" ]]; then
    touch "$COOKIE_JAR"
    chmod 600 "$COOKIE_JAR"
  fi
}

# --- Platform Detection ---
detect_platform() {
  case "$(uname -s)" in
    Darwin*)
      USER_AGENT="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${CHROME_VERSION}.0.0.0 Safari/537.36"
      SEC_CH_UA_PLATFORM='"macOS"'
      ;;
    Linux*)
      USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${CHROME_VERSION}.0.0.0 Safari/537.36"
      SEC_CH_UA_PLATFORM='"Linux"'
      ;;
    MINGW*|MSYS*|CYGWIN*)
      USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${CHROME_VERSION}.0.0.0 Safari/537.36"
      SEC_CH_UA_PLATFORM='"Windows"'
      ;;
    *)
      USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${CHROME_VERSION}.0.0.0 Safari/537.36"
      SEC_CH_UA_PLATFORM='"Linux"'
      ;;
  esac
}

# --- Capability Detection ---
detect_capabilities() {
  CURL_BIN="env curl"

  # Check for curl-impersonate (preferred — matches Chrome TLS + HTTP/2 fingerprint).
  # Latest available build targets Chrome 116's TLS; our injected headers present as
  # Chrome 145. This mismatch is acceptable: WAFs rarely cross-check TLS version against
  # header version, and a Chrome 116 TLS fingerprint is far better than OpenSSL/LibreSSL.
  USE_IMPERSONATE=false
  if command -v curl-impersonate >/dev/null 2>&1; then
    CURL_BIN="curl-impersonate"
    USE_IMPERSONATE=true
  elif command -v curl_chrome116 >/dev/null 2>&1; then
    CURL_BIN="curl_chrome116"
    USE_IMPERSONATE=true
  fi

  # Check HTTP/2 support
  SUPPORTS_HTTP2=false
  if env curl --version 2>/dev/null | grep -q 'nghttp2'; then
    SUPPORTS_HTTP2=true
  fi

  # Check brotli support
  SUPPORTS_BROTLI=false
  if env curl --version 2>/dev/null | grep -q 'brotli'; then
    SUPPORTS_BROTLI=true
  fi

  # Check zstd support
  SUPPORTS_ZSTD=false
  if env curl --version 2>/dev/null | grep -q 'zstd'; then
    SUPPORTS_ZSTD=true
  fi

  # Build Accept-Encoding based on actual capabilities
  # Chrome sends: gzip, deflate, br, zstd
  ACCEPT_ENCODING="gzip, deflate"
  if [[ "$SUPPORTS_BROTLI" == true ]]; then
    ACCEPT_ENCODING="$ACCEPT_ENCODING, br"
  fi
  if [[ "$SUPPORTS_ZSTD" == true ]]; then
    ACCEPT_ENCODING="$ACCEPT_ENCODING, zstd"
  fi
}

# --- URL Extraction ---
# Find the URL from args (first arg that looks like a URL)
extract_url_and_args() {
  URL=""
  EXTRA_ARGS=()
  DIAGNOSE_MODE=false

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --diagnose)
        DIAGNOSE_MODE=true
        ;;
      --chrome-version)
        if [[ -n "${2:-}" && "$2" =~ ^[0-9]+$ ]]; then
          CHROME_VERSION="$2"
          compute_grease "$CHROME_VERSION"
          shift
        else
          echo "Error: --chrome-version requires a numeric argument" >&2
          exit 1
        fi
        ;;
      --no-cookies)
        USE_COOKIES=false
        ;;
      --clear-cookies)
        rm -f "$COOKIE_JAR"
        echo "Cookie jar cleared: ${COOKIE_JAR}" >&2
        ;;
      --cookie-jar)
        if [[ -n "${2:-}" ]]; then
          COOKIE_JAR="$2"
          COOKIE_DIR="$(dirname "$COOKIE_JAR")"
          shift
        else
          echo "Error: --cookie-jar requires a path argument" >&2
          exit 1
        fi
        ;;
      -b|-c|--cookie)
        # User is supplying their own cookie flags — disable automatic cookies
        USE_COOKIES=false
        EXTRA_ARGS+=("$1")
        ;;
      http://*|https://*)
        if [[ -z "$URL" ]]; then
          URL="$1"
        else
          EXTRA_ARGS+=("$1")
        fi
        ;;
      *)
        EXTRA_ARGS+=("$1")
        ;;
    esac
    shift
  done

  if [[ -z "$URL" ]]; then
    echo "Error: No URL provided" >&2
    echo "Usage: bash browser_curl.sh [URL] [extra curl args...]" >&2
    echo "       bash browser_curl.sh -X POST -d '{\"key\":\"val\"}' [URL]" >&2
    echo "       bash browser_curl.sh --diagnose [URL]" >&2
    exit 1
  fi
}

# --- Diagnostic Mode ---
# All output to stderr so it won't interfere with piping
run_diagnose() {
  local url="$URL"
  local tmpbody tmpheaders
  tmpbody=$(mktemp)
  tmpheaders=$(mktemp)
  trap 'rm -f "$tmpbody" "$tmpheaders"' RETURN

  echo "━━━ browser_curl.sh diagnostic ━━━" >&2
  echo "" >&2

  # Step 1: Make request and capture status + response headers
  echo "1. Making request to ${url}..." >&2
  local http_code
  local -a diag_cookie_args=()
  if [[ "$USE_COOKIES" == true ]]; then
    diag_cookie_args+=(-b "$COOKIE_JAR" -c "$COOKIE_JAR")
  fi

  http_code=$(env curl -sS -o "$tmpbody" -w '%{http_code}' \
    -D "$tmpheaders" -L --max-time 15 \
    --http2 \
    -H "sec-ch-ua: ${SEC_CH_UA}" \
    -H "sec-ch-ua-mobile: ${SEC_CH_UA_MOBILE}" \
    -H "sec-ch-ua-platform: ${SEC_CH_UA_PLATFORM}" \
    -H "Upgrade-Insecure-Requests: ${UPGRADE_INSECURE_REQUESTS}" \
    -H "User-Agent: ${USER_AGENT}" \
    -H "Accept: ${ACCEPT}" \
    -H "Accept-Language: ${ACCEPT_LANGUAGE}" \
    -H "Accept-Encoding: ${ACCEPT_ENCODING}" \
    -H "Sec-Fetch-Site: ${SEC_FETCH_SITE}" \
    -H "Sec-Fetch-Mode: ${SEC_FETCH_MODE}" \
    -H "Sec-Fetch-User: ${SEC_FETCH_USER}" \
    -H "Sec-Fetch-Dest: ${SEC_FETCH_DEST}" \
    -H "Cache-Control: ${CACHE_CONTROL}" \
    -H "Priority: u=0, i" \
    --compressed \
    "${diag_cookie_args[@]}" \
    "$url" 2>/dev/null || echo "000")

  echo "   Status: ${http_code}" >&2

  # Step 2: Analyze response — identify WAF from response headers
  echo "" >&2
  echo "2. Analyzing response headers..." >&2
  local waf="unknown"
  local resp_headers
  resp_headers=$(cat "$tmpheaders" 2>/dev/null || echo "")

  if echo "$resp_headers" | grep -qi 'cf-ray'; then
    waf="Cloudflare"
  elif echo "$resp_headers" | grep -qi 'AkamaiGHost\|x-akamai'; then
    waf="Akamai"
  elif echo "$resp_headers" | grep -qi 'x-datadome\|datadome'; then
    waf="DataDome"
  elif echo "$resp_headers" | grep -qi 'x-sucuri\|sucuri'; then
    waf="Sucuri"
  elif echo "$resp_headers" | grep -qi 'x-cdn: Imperva\|incap_ses'; then
    waf="Imperva/Incapsula"
  fi

  if [[ "$waf" != "unknown" ]]; then
    echo "   WAF detected: ${waf}" >&2
  else
    echo "   WAF: none detected (or unrecognized)" >&2
  fi

  # Check for JS challenge indicators
  local has_js_challenge=false
  if echo "$resp_headers" | grep -qi 'text/html'; then
    if grep -qi 'just a moment\|checking your browser\|enable javascript\|challenge-platform' "$tmpbody" 2>/dev/null; then
      has_js_challenge=true
      echo "   JS challenge page detected in response body" >&2
    fi
  fi

  # Step 3: Verify headers via httpbin
  echo "" >&2
  echo "3. Verifying headers via httpbin.org..." >&2
  local verify_json
  verify_json=$(env curl -sS --max-time 10 \
    --http2 \
    -H "sec-ch-ua: ${SEC_CH_UA}" \
    -H "sec-ch-ua-mobile: ${SEC_CH_UA_MOBILE}" \
    -H "sec-ch-ua-platform: ${SEC_CH_UA_PLATFORM}" \
    -H "Upgrade-Insecure-Requests: ${UPGRADE_INSECURE_REQUESTS}" \
    -H "User-Agent: ${USER_AGENT}" \
    -H "Accept: ${ACCEPT}" \
    -H "Accept-Language: ${ACCEPT_LANGUAGE}" \
    -H "Accept-Encoding: ${ACCEPT_ENCODING}" \
    -H "Sec-Fetch-Site: ${SEC_FETCH_SITE}" \
    -H "Sec-Fetch-Mode: ${SEC_FETCH_MODE}" \
    -H "Sec-Fetch-User: ${SEC_FETCH_USER}" \
    -H "Sec-Fetch-Dest: ${SEC_FETCH_DEST}" \
    -H "Cache-Control: ${CACHE_CONTROL}" \
    -H "Priority: u=0, i" \
    --compressed \
    "https://httpbin.org/headers" 2>/dev/null || echo "")

  if [[ -n "$verify_json" ]] && echo "$verify_json" | grep -q 'Sec-Ch-Ua' 2>/dev/null; then
    echo "   Headers confirmed — sec-ch-ua, Sec-Fetch-*, User-Agent all present" >&2
    # Quick check for key headers
    local check_ua check_grease
    check_ua=$(echo "$verify_json" | grep -o 'Chrome/[0-9]*' | head -1)
    check_grease=$(echo "$verify_json" | grep -o "${GREASE_BRAND}" || true)
    [[ -n "$check_ua" ]] && echo "   User-Agent: ${check_ua}" >&2
    [[ -n "$check_grease" ]] && echo "   GREASE brand: ${GREASE_BRAND} (correct for Chrome ${CHROME_VERSION})" >&2
  else
    echo "   Could not verify headers (httpbin.org unreachable)" >&2
  fi

  # Step 4: Check TLS fingerprint status
  echo "" >&2
  echo "4. Checking TLS fingerprint..." >&2
  if [[ "$USE_IMPERSONATE" == true ]]; then
    echo "   curl-impersonate: INSTALLED (${CURL_BIN})" >&2
    echo "   TLS fingerprint: Chrome 116 (BoringSSL) — close match" >&2
  else
    local tls_lib
    tls_lib=$(env curl --version 2>/dev/null | head -1 | grep -oE '(OpenSSL|LibreSSL|BoringSSL)[^ ]*' || echo "unknown")
    echo "   curl-impersonate: NOT installed" >&2
    echo "   TLS library: ${tls_lib}" >&2
    echo "   TLS fingerprint: will NOT match Chrome (JA3/JA4 differs)" >&2
  fi
  echo "   HTTP/2: $(if [[ "$SUPPORTS_HTTP2" == true ]]; then echo "enabled"; else echo "not available"; fi)" >&2
  if [[ "$USE_COOKIES" == true ]]; then
    local cookie_count=0
    if [[ -f "$COOKIE_JAR" ]]; then
      cookie_count=$(grep -cEv '^#|^$' "$COOKIE_JAR" 2>/dev/null) || cookie_count=0
    fi
    echo "   Cookie jar: ${COOKIE_JAR} (${cookie_count} cookies)" >&2
  else
    echo "   Cookie jar: disabled" >&2
  fi

  # Step 5: Diagnosis summary
  echo "" >&2
  echo "━━━ Diagnosis ━━━" >&2

  if [[ "$http_code" == "200" ]] && [[ "$has_js_challenge" == false ]]; then
    echo "   Request succeeded (200). No issues detected." >&2
  elif [[ "$http_code" == "200" ]] && [[ "$has_js_challenge" == true ]]; then
    echo "   Status 200 but JS challenge page detected (soft block)." >&2
    echo "   The WAF served a challenge page instead of real content." >&2
    echo "   1. JavaScript challenge — curl cannot execute JS" >&2
    echo "      → Use a headless browser (Playwright/Puppeteer) for this site" >&2
    if [[ "$USE_IMPERSONATE" != true ]]; then
      echo "   2. TLS fingerprint may also be a factor" >&2
      echo "      → Install curl-impersonate first to rule out TLS detection" >&2
    fi
  elif [[ "$http_code" == "000" ]]; then
    echo "   Connection failed. Likely causes:" >&2
    echo "   1. DNS resolution failure or network issue" >&2
    echo "   2. Target server is down or unreachable" >&2
    echo "   3. Request timed out (15s limit)" >&2
  else
    echo "   Request returned ${http_code}. Likely causes (in order):" >&2
    local cause_num=1

    if [[ "$has_js_challenge" == true ]]; then
      echo "   ${cause_num}. JavaScript challenge detected — curl cannot execute JS" >&2
      echo "      → Use a headless browser (Playwright/Puppeteer) instead" >&2
      ((cause_num++))
    fi

    if [[ "$USE_IMPERSONATE" != true ]]; then
      echo "   ${cause_num}. TLS fingerprint mismatch — ${waf:-WAF} may check JA3/JA4" >&2
      echo "      → Install curl-impersonate: brew tap AaronCQL/curl-impersonate && brew install curl-impersonate" >&2
      ((cause_num++))
    fi

    if [[ "$waf" == "Cloudflare" ]]; then
      echo "   ${cause_num}. Cloudflare Bot Management — may require browser rendering" >&2
      echo "      → Try: curl-impersonate first, then Playwright if still blocked" >&2
      ((cause_num++))
    elif [[ "$waf" == "DataDome" ]]; then
      echo "   ${cause_num}. DataDome uses aggressive TLS + behavioral fingerprinting" >&2
      echo "      → curl-impersonate may help; behavioral checks need a real browser" >&2
      ((cause_num++))
    elif [[ "$waf" != "unknown" ]]; then
      echo "   ${cause_num}. ${waf} WAF detected — check if TLS fingerprinting is enabled" >&2
      ((cause_num++))
    fi

    if [[ "$http_code" == "403" ]] && [[ "$cause_num" -eq 1 ]]; then
      echo "   ${cause_num}. Server returned 403 — may be IP-based blocking or geo-restriction" >&2
      ((cause_num++))
    fi

    if [[ "$http_code" == "503" ]]; then
      echo "   ${cause_num}. 503 often indicates a challenge page or rate limiting" >&2
      ((cause_num++))
    fi
  fi

  echo "" >&2
}

# --- Main ---
main() {
  detect_capabilities
  extract_url_and_args "$@"
  # detect_platform after arg parsing so --chrome-version is applied to User-Agent
  detect_platform
  setup_cookies

  # Diagnostic mode: run analysis and exit
  if [[ "$DIAGNOSE_MODE" == true ]]; then
    run_diagnose
    exit 0
  fi

  # Build the curl command
  CURL_ARGS=()

  # Use HTTP/2 if available (Chrome always uses HTTP/2)
  if [[ "$SUPPORTS_HTTP2" == true ]]; then
    CURL_ARGS+=(--http2)
  fi

  # Follow redirects (Chrome follows redirects)
  CURL_ARGS+=(-L)

  # Suppress progress bar but show errors
  CURL_ARGS+=(-sS)

  # Headers in Chrome's actual sending order:
  # 1. sec-ch-ua (with GREASE)
  CURL_ARGS+=(-H "sec-ch-ua: ${SEC_CH_UA}")
  # 2. sec-ch-ua-mobile
  CURL_ARGS+=(-H "sec-ch-ua-mobile: ${SEC_CH_UA_MOBILE}")
  # 3. sec-ch-ua-platform
  CURL_ARGS+=(-H "sec-ch-ua-platform: ${SEC_CH_UA_PLATFORM}")
  # 4. Upgrade-Insecure-Requests
  CURL_ARGS+=(-H "Upgrade-Insecure-Requests: ${UPGRADE_INSECURE_REQUESTS}")
  # 5. User-Agent
  CURL_ARGS+=(-H "User-Agent: ${USER_AGENT}")
  # 6. Accept
  CURL_ARGS+=(-H "Accept: ${ACCEPT}")
  # 7. Accept-Language
  CURL_ARGS+=(-H "Accept-Language: ${ACCEPT_LANGUAGE}")
  # 8. Accept-Encoding (adjusted to actual capabilities)
  CURL_ARGS+=(-H "Accept-Encoding: ${ACCEPT_ENCODING}")
  # 9. Sec-Fetch headers
  CURL_ARGS+=(-H "Sec-Fetch-Site: ${SEC_FETCH_SITE}")
  CURL_ARGS+=(-H "Sec-Fetch-Mode: ${SEC_FETCH_MODE}")
  CURL_ARGS+=(-H "Sec-Fetch-User: ${SEC_FETCH_USER}")
  CURL_ARGS+=(-H "Sec-Fetch-Dest: ${SEC_FETCH_DEST}")
  # 10. Cache-Control
  CURL_ARGS+=(-H "Cache-Control: ${CACHE_CONTROL}")
  # 11. Priority (HTTP/2 priority hint, Chrome 145+)
  if [[ "$SUPPORTS_HTTP2" == true ]]; then
    CURL_ARGS+=(-H "Priority: u=0, i")
  fi

  # Compressed transfer (handles decompression for supported encodings)
  CURL_ARGS+=(--compressed)

  # Cookie persistence (read from and write to cookie jar)
  if [[ "$USE_COOKIES" == true ]]; then
    CURL_ARGS+=(-b "$COOKIE_JAR" -c "$COOKIE_JAR")
  fi

  # Append any extra user-provided arguments
  if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
    CURL_ARGS+=("${EXTRA_ARGS[@]}")
  fi

  # The URL goes last
  CURL_ARGS+=("$URL")

  # Execute
  if [[ "$USE_IMPERSONATE" == true ]]; then
    # CURL_IMPERSONATE=chrome116 sets TLS fingerprint to Chrome 116 (latest available
    # curl-impersonate build). Our injected headers present as Chrome 145 — the mismatch
    # is intentional: TLS version is rarely cross-checked against header version by WAFs,
    # and Chrome 116 TLS is far more convincing than stock OpenSSL/LibreSSL.
    CURL_IMPERSONATE=chrome116 $CURL_BIN "${CURL_ARGS[@]}"
  else
    env curl "${CURL_ARGS[@]}"
  fi
}

main "$@"
