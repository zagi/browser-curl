#Requires -Version 5.1
<#
.SYNOPSIS
    PowerShell curl wrapper that mimics Chrome 145 browser fingerprint.

.DESCRIPTION
    Injects browser-authentic headers (Sec-CH-UA, Client Hints, Sec-Fetch-*)
    to bypass WAF header fingerprinting on Windows. Uses curl.exe explicitly
    to avoid PowerShell's Invoke-WebRequest alias.

.PARAMETER Url
    The URL to request.

.PARAMETER Diagnose
    Run 4-step diagnostic analysis instead of a normal request.

.PARAMETER ChromeVersion
    Override the Chrome version (default: 145). Changes GREASE brand,
    version, User-Agent, and sec-ch-ua header.

.PARAMETER NoCookies
    Disable automatic cookie persistence.

.PARAMETER ClearCookies
    Remove the cookie jar file before making the request.

.PARAMETER CookieJar
    Path to a custom cookie jar file.

.EXAMPLE
    .\browser_curl.ps1 https://example.com

.EXAMPLE
    .\browser_curl.ps1 -Diagnose https://example.com

.EXAMPLE
    .\browser_curl.ps1 -ChromeVersion 146 https://httpbin.org/headers
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Url,

    [switch]$Diagnose,
    [switch]$NoCookies,
    [switch]$ClearCookies,

    [string]$CookieJar,
    [int]$ChromeVersion = 145,

    [Parameter(ValueFromRemainingArguments)]
    [string[]]$ExtraArgs
)

$ErrorActionPreference = 'Stop'

# --- Verify curl.exe is available ---
$curlExe = Get-Command curl.exe -ErrorAction SilentlyContinue
if (-not $curlExe) {
    Write-Error @"
curl.exe not found. On Windows, PowerShell's 'curl' is an alias for Invoke-WebRequest.
Install curl from https://curl.se/windows/ or via:
  winget install curl
  scoop install curl
Then ensure curl.exe is on your PATH.
"@
    exit 1
}

# --- GREASE Computation ---
function Compute-Grease {
    param([int]$Seed)

    $chars = @(' ', '(', ':', '-', '.', '/', ')', ';', '=', '?', '_')
    $c1 = $chars[$Seed % 11]
    $c2 = $chars[($Seed + 1) % 11]
    $brand = "Not${c1}A${c2}Brand"

    $versions = @('8', '99', '24')
    $ver = $versions[$Seed % 3]

    $grease = "`"${brand}`";v=`"${ver}`""
    $chromium = "`"Chromium`";v=`"${Seed}`""
    $chrome = "`"Google Chrome`";v=`"${Seed}`""

    # Permutation over base [GREASE, Chromium, Chrome]
    $perm = $Seed % 6
    $secChUa = switch ($perm) {
        0 { "${grease}, ${chromium}, ${chrome}" }
        1 { "${grease}, ${chrome}, ${chromium}" }
        2 { "${chromium}, ${grease}, ${chrome}" }
        3 { "${chromium}, ${chrome}, ${grease}" }
        4 { "${chrome}, ${grease}, ${chromium}" }
        5 { "${chrome}, ${chromium}, ${grease}" }
    }

    return @{
        Brand    = $brand
        Version  = $ver
        SecChUa  = $secChUa
    }
}

# --- Capability Detection ---
function Detect-Capabilities {
    $version_output = & curl.exe --version 2>$null | Out-String

    $caps = @{
        Http2  = $version_output -match 'nghttp2'
        Brotli = $version_output -match 'brotli'
        Zstd   = $version_output -match 'zstd'
    }

    $encoding = 'gzip, deflate'
    if ($caps.Brotli) { $encoding += ', br' }
    if ($caps.Zstd) { $encoding += ', zstd' }
    $caps.AcceptEncoding = $encoding

    return $caps
}

# --- Cookie Setup ---
$cookieDir = Join-Path $env:USERPROFILE '.browser-curl'
$cookieFile = if ($CookieJar) { $CookieJar } else { Join-Path $cookieDir 'cookies.txt' }
$useCookies = -not $NoCookies

# Check if user passed -b or -c in ExtraArgs — disable auto cookies
if ($ExtraArgs -and ($ExtraArgs -contains '-b' -or $ExtraArgs -contains '-c' -or $ExtraArgs -contains '--cookie')) {
    $useCookies = $false
}

if ($ClearCookies) {
    if (Test-Path $cookieFile) {
        Remove-Item $cookieFile -Force
        Write-Host "Cookie jar cleared: $cookieFile" -ForegroundColor Yellow
    }
}

if ($useCookies) {
    if (-not (Test-Path $cookieDir)) {
        New-Item -ItemType Directory -Path $cookieDir -Force | Out-Null
    }
    if (-not (Test-Path $cookieFile)) {
        New-Item -ItemType File -Path $cookieFile -Force | Out-Null
    }
}

# --- Compute values ---
$grease = Compute-Grease -Seed $ChromeVersion
$caps = Detect-Capabilities

$userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${ChromeVersion}.0.0.0 Safari/537.36"
$accept = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
$acceptLanguage = 'en-US,en;q=0.9'

# --- Find URL from ExtraArgs if not provided as named parameter ---
if (-not $Url -and $ExtraArgs) {
    $remaining = @()
    foreach ($arg in $ExtraArgs) {
        if (-not $Url -and $arg -match '^https?://') {
            $Url = $arg
        }
        else {
            $remaining += $arg
        }
    }
    $ExtraArgs = $remaining
}

if (-not $Url) {
    Write-Error @"
No URL provided.
Usage: .\browser_curl.ps1 [URL] [extra curl args...]
       .\browser_curl.ps1 -Diagnose [URL]
       .\browser_curl.ps1 -ChromeVersion 146 [URL]
"@
    exit 1
}

# --- Diagnostic Mode ---
if ($Diagnose) {
    $tmpBody = [System.IO.Path]::GetTempFileName()
    $tmpHeaders = [System.IO.Path]::GetTempFileName()

    try {
        Write-Host "`n━━━ browser_curl.ps1 diagnostic ━━━`n" -ForegroundColor Cyan

        # Step 1: Make request
        Write-Host "1. Making request to ${Url}..." -ForegroundColor White
        $diagArgs = @(
            '-sS', '-o', $tmpBody, '-w', '%{http_code}',
            '-D', $tmpHeaders, '-L', '--max-time', '15'
        )
        if ($caps.Http2) { $diagArgs += '--http2' }
        $diagArgs += @(
            '-H', "sec-ch-ua: $($grease.SecChUa)",
            '-H', 'sec-ch-ua-mobile: ?0',
            '-H', 'sec-ch-ua-platform: "Windows"',
            '-H', 'Upgrade-Insecure-Requests: 1',
            '-H', "User-Agent: $userAgent",
            '-H', "Accept: $accept",
            '-H', "Accept-Language: $acceptLanguage",
            '-H', "Accept-Encoding: $($caps.AcceptEncoding)",
            '-H', 'Sec-Fetch-Site: none',
            '-H', 'Sec-Fetch-Mode: navigate',
            '-H', 'Sec-Fetch-User: ?1',
            '-H', 'Sec-Fetch-Dest: document',
            '-H', 'Cache-Control: max-age=0',
            '-H', 'Priority: u=0, i',
            '--compressed'
        )
        if ($useCookies) {
            $diagArgs += @('-b', $cookieFile, '-c', $cookieFile)
        }
        $diagArgs += $Url

        $httpCode = & curl.exe @diagArgs 2>$null
        if (-not $httpCode) { $httpCode = '000' }
        Write-Host "   Status: $httpCode"

        # Step 2: Identify WAF
        Write-Host "`n2. Analyzing response headers..." -ForegroundColor White
        $respHeaders = if (Test-Path $tmpHeaders) { Get-Content $tmpHeaders -Raw -ErrorAction SilentlyContinue } else { '' }
        $waf = 'unknown'
        if ($respHeaders -match 'cf-ray') { $waf = 'Cloudflare' }
        elseif ($respHeaders -match 'AkamaiGHost|x-akamai') { $waf = 'Akamai' }
        elseif ($respHeaders -match 'x-datadome|datadome') { $waf = 'DataDome' }
        elseif ($respHeaders -match 'x-sucuri|sucuri') { $waf = 'Sucuri' }
        elseif ($respHeaders -match 'x-cdn: Imperva|incap_ses') { $waf = 'Imperva/Incapsula' }

        if ($waf -ne 'unknown') {
            Write-Host "   WAF detected: $waf"
        }
        else {
            Write-Host "   WAF: none detected (or unrecognized)"
        }

        $hasJsChallenge = $false
        if ($respHeaders -match 'text/html') {
            $body = if (Test-Path $tmpBody) { Get-Content $tmpBody -Raw -ErrorAction SilentlyContinue } else { '' }
            if ($body -match 'just a moment|checking your browser|enable javascript|challenge-platform') {
                $hasJsChallenge = $true
                Write-Host "   JS challenge page detected in response body"
            }
        }

        # Step 3: Verify headers
        Write-Host "`n3. Verifying headers via httpbin.org..." -ForegroundColor White
        $verifyArgs = @('-sS', '--max-time', '10')
        if ($caps.Http2) { $verifyArgs += '--http2' }
        $verifyArgs += @(
            '-H', "sec-ch-ua: $($grease.SecChUa)",
            '-H', 'sec-ch-ua-mobile: ?0',
            '-H', 'sec-ch-ua-platform: "Windows"',
            '-H', 'Upgrade-Insecure-Requests: 1',
            '-H', "User-Agent: $userAgent",
            '-H', "Accept: $accept",
            '-H', "Accept-Language: $acceptLanguage",
            '-H', "Accept-Encoding: $($caps.AcceptEncoding)",
            '-H', 'Sec-Fetch-Site: none',
            '-H', 'Sec-Fetch-Mode: navigate',
            '-H', 'Sec-Fetch-User: ?1',
            '-H', 'Sec-Fetch-Dest: document',
            '-H', 'Cache-Control: max-age=0',
            '-H', 'Priority: u=0, i',
            '--compressed',
            'https://httpbin.org/headers'
        )
        $verifyJson = & curl.exe @verifyArgs 2>$null
        if ($verifyJson -match 'Sec-Ch-Ua') {
            Write-Host "   Headers confirmed - sec-ch-ua, Sec-Fetch-*, User-Agent all present"
            if ($verifyJson -match 'Chrome/(\d+)') { Write-Host "   User-Agent: Chrome/$($Matches[1])" }
            if ($verifyJson -match [regex]::Escape($grease.Brand)) {
                Write-Host "   GREASE brand: $($grease.Brand) (correct for Chrome $ChromeVersion)"
            }
        }
        else {
            Write-Host "   Could not verify headers (httpbin.org unreachable)"
        }

        # Step 4: TLS + cookie status
        Write-Host "`n4. Checking TLS fingerprint..." -ForegroundColor White
        $tlsLib = if (& curl.exe --version 2>$null | Select-String -Pattern '(OpenSSL|LibreSSL|BoringSSL)\S*' -AllMatches) {
            $Matches[0].Value
        }
        else { 'unknown' }
        Write-Host "   curl-impersonate: NOT available (Windows)"
        Write-Host "   TLS library: $tlsLib"
        Write-Host "   TLS fingerprint: will NOT match Chrome (JA3/JA4 differs)"
        $http2Status = if ($caps.Http2) { 'enabled' } else { 'not available' }
        Write-Host "   HTTP/2: $http2Status"

        if ($useCookies) {
            $cookieCount = 0
            if (Test-Path $cookieFile) {
                $cookieCount = @(Get-Content $cookieFile | Where-Object { $_ -and $_ -notmatch '^#' }).Count
            }
            Write-Host "   Cookie jar: $cookieFile ($cookieCount cookies)"
        }
        else {
            Write-Host "   Cookie jar: disabled"
        }

        # Step 5: Summary
        Write-Host "`n━━━ Diagnosis ━━━" -ForegroundColor Cyan
        if ($httpCode -eq '200' -and -not $hasJsChallenge) {
            Write-Host "   Request succeeded (200). No issues detected."
        }
        elseif ($httpCode -eq '200' -and $hasJsChallenge) {
            Write-Host "   Status 200 but JS challenge page detected (soft block)."
            Write-Host "   1. JavaScript challenge - curl cannot execute JS"
            Write-Host "      -> Use a headless browser (Playwright/Puppeteer) for this site"
        }
        elseif ($httpCode -eq '000') {
            Write-Host "   Connection failed. Likely causes:"
            Write-Host "   1. DNS resolution failure or network issue"
            Write-Host "   2. Target server is down or unreachable"
            Write-Host "   3. Request timed out (15s limit)"
        }
        else {
            Write-Host "   Request returned $httpCode. Likely causes (in order):"
            $causeNum = 1
            if ($hasJsChallenge) {
                Write-Host "   $causeNum. JavaScript challenge detected - curl cannot execute JS"
                Write-Host "      -> Use a headless browser (Playwright/Puppeteer) instead"
                $causeNum++
            }
            Write-Host "   $causeNum. TLS fingerprint mismatch - $waf may check JA3/JA4"
            Write-Host "      -> curl-impersonate is not available on Windows; consider WSL"
            $causeNum++
            if ($waf -eq 'Cloudflare') {
                Write-Host "   $causeNum. Cloudflare Bot Management - may require browser rendering"
                $causeNum++
            }
            elseif ($waf -eq 'DataDome') {
                Write-Host "   $causeNum. DataDome uses aggressive TLS + behavioral fingerprinting"
                $causeNum++
            }
        }
        Write-Host ''
    }
    finally {
        Remove-Item $tmpBody, $tmpHeaders -Force -ErrorAction SilentlyContinue
    }
    exit 0
}

# --- Build curl arguments ---
$CurlArgs = @()

if ($caps.Http2) { $CurlArgs += '--http2' }

$CurlArgs += @('-L', '-sS')

# Headers in Chrome's actual sending order
$CurlArgs += @(
    '-H', "sec-ch-ua: $($grease.SecChUa)",
    '-H', 'sec-ch-ua-mobile: ?0',
    '-H', 'sec-ch-ua-platform: "Windows"',
    '-H', 'Upgrade-Insecure-Requests: 1',
    '-H', "User-Agent: $userAgent",
    '-H', "Accept: $accept",
    '-H', "Accept-Language: $acceptLanguage",
    '-H', "Accept-Encoding: $($caps.AcceptEncoding)",
    '-H', 'Sec-Fetch-Site: none',
    '-H', 'Sec-Fetch-Mode: navigate',
    '-H', 'Sec-Fetch-User: ?1',
    '-H', 'Sec-Fetch-Dest: document',
    '-H', 'Cache-Control: max-age=0'
)

if ($caps.Http2) {
    $CurlArgs += @('-H', 'Priority: u=0, i')
}

$CurlArgs += '--compressed'

# Cookie persistence
if ($useCookies) {
    $CurlArgs += @('-b', $cookieFile, '-c', $cookieFile)
}

# Extra user-provided arguments
if ($ExtraArgs) {
    $CurlArgs += $ExtraArgs
}

# URL goes last
$CurlArgs += $Url

# Execute
& curl.exe @CurlArgs
