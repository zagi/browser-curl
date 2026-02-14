# GREASE Brand Rotation

Chrome rotates a fake brand in `sec-ch-ua` every release. Values are deterministic from the version number.

## Why GREASE Is Deterministic

GREASE (Generate Random Extensions And Sustain Extensibility) prevents servers from hardcoding a list of "valid" browser brands. The name is misleading — despite "Random" in the acronym, the values are **fully deterministic** per Chrome version. Every Chrome 145 installation worldwide sends the exact same GREASE brand.

This is intentional:
- **If GREASE were random**, each request from the same browser would have a different brand, which WAFs could detect as anomalous behavior (real Chrome doesn't change its brand mid-session)
- **If GREASE varied per installation**, sites couldn't reliably parse the header — the point is to force servers to ignore unknown brands, not to create unpredictable values
- **Deterministic rotation** means the brand changes only when Chrome updates, which is the exact cadence servers should expect

Randomizing GREASE in a spoofing tool would be counterproductive: a value that doesn't match any known Chrome version is more suspicious than one that matches exactly.

## Algorithm

```
CHARS = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"]
Brand   = "Not" + CHARS[seed % 11] + "A" + CHARS[(seed+1) % 11] + "Brand"
Version = ["8", "99", "24"][seed % 3]
Order   = [{0,1,2}, {0,2,1}, {1,0,2}, {1,2,0}, {2,0,1}, {2,1,0}][seed % 6]
```

Where `seed` = Chrome major version. Order permutes `[GREASE, Chromium, Chrome]` position in the header.

## Chrome 145

`seed=145` → `CHARS[2]=":"`, `CHARS[3]="-"` → `"Not:A-Brand"`, version `"99"`, order `{0,2,1}`

Result: `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`

## Nearby Versions

| Chrome | Brand | Version | Full sec-ch-ua |
|--------|-------|---------|---------------|
| 144 | `Not(A:Brand` | `8` | `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"` |
| **145** | **`Not:A-Brand`** | **`99`** | **`"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`** |
| 146 | `Not-A.Brand` | `24` | `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"` |
| 147 | `Not.A/Brand` | `8` | `"Chromium";v="147", "Google Chrome";v="147", "Not.A/Brand";v="8"` |

## Using `--chrome-version`

Instead of manually updating header values when Chrome releases a new version, use the `--chrome-version` flag:

```bash
# Use Chrome 146 headers
bash browser_curl.sh --chrome-version 146 https://example.com

# Verify the computed headers
bash browser_curl.sh --chrome-version 146 https://httpbin.org/headers | jq .
```

This computes the correct GREASE brand, version, ordering, and User-Agent string automatically. The `compute_grease()` function in `browser_curl.sh` implements the same algorithm as Chromium's `GetGreasedBrandVersionForGeneration`.

## How to Verify

1. Check the latest Chrome stable version at [Chrome Releases](https://chromereleases.googleblog.com/)
2. Run with the new version: `bash browser_curl.sh --chrome-version N https://httpbin.org/headers | jq .`
3. Compare against a real Chrome browser visiting `https://httpbin.org/headers`

Source: [Chromium `GetGreasedBrandVersionForGeneration`](https://chromium.googlesource.com/chromium/src/+/main/components/embedder_support/user_agent_utils.cc)
