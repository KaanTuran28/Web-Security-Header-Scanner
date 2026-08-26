# Web Security Header Scan Report

- **Target URL:** https://github.com
- **Scanned at:** 2026-08-20 15:24 UTC
- **Score:** 5/6 (B)

| Header | Present | Value | Recommendation |
|---|---|---|---|
| Strict-Transport-Security | Yes | max-age=31536000; includeSubdomains; preload | OK |
| Content-Security-Policy | Yes | default-src 'none'; base-uri 'self'; child-src github.githubassets.com github.com/assets-cdn/worker/… (truncated) | OK |
| X-Content-Type-Options | Yes | nosniff | OK |
| X-Frame-Options | Yes | deny | OK |
| Referrer-Policy | Yes | origin-when-cross-origin, strict-origin-when-cross-origin | OK |
| Permissions-Policy | No | — | Define a Permissions-Policy to disable unneeded browser features (camera, mic, geolocation, ...). |
