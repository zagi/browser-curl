# GREASE Brand Rotation

Chrome rotates a fake brand in `sec-ch-ua` every release. Values are deterministic from the version number.

## Algorithm

```
CHARS = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"]
Brand   = "Not" + CHARS[seed % 11] + "A" + CHARS[(seed+1) % 11] + "Brand"
Version = ["8", "99", "24"][seed % 3]
Order   = [{0,1,2}, {0,2,1}, {1,0,2}, {1,2,0}, {2,0,1}, {2,1,0}][seed % 6]
```

Where `seed` = Chrome major version. Order permutes `[GREASE, Chrome, Chromium]` position in the header.

## Chrome 145

`seed=145` → `CHARS[2]=":"`, `CHARS[3]="-"` → `"Not:A-Brand"`, version `"99"`, order `{0,2,1}`

Result: `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`

## Nearby Versions

| Chrome | Brand | Version |
|--------|-------|---------|
| 144 | `Not(A:Brand` | `8` |
| **145** | **`Not:A-Brand`** | **`99`** |
| 146 | `Not-A.Brand` | `24` |
| 147 | `Not.A/Brand` | `99` |

## How to Update

1. Compute brand/version using the algorithm above
2. Update `sec-ch-ua` header value and `Chrome/VERSION` in User-Agent
3. Verify against live Chrome via `https://httpbin.org/headers`

Source: [Chromium `GetGreasedBrandVersionForGeneration`](https://chromium.googlesource.com/chromium/src/+/main/components/embedder_support/user_agent_utils.cc)
