# Changelog

## 1.0.4 — 2026-05-16

### Fixed

- Add `types` to `package.json` `exports` for TypeScript 5+ (`NodeNext` / `Bundler` resolution)
- Ship `src/index.d.ts` explicitly in the npm package

## 1.0.3 — 2026-05-16

- Published under `@pq-jwt/core` org scope

## 1.0.0 — 2025-05-16

### Initial Release

- ML-DSA-44, ML-DSA-65, ML-DSA-87 (NIST FIPS 204)
- SLH-DSA-SHA2-128s (NIST FIPS 205)
- sign(), verify(), decode(), refresh()
- generateKeyPair(), exportKey(), importKey()
- algorithmInfo()
- Full typed error hierarchy
- 35/35 tests passing
