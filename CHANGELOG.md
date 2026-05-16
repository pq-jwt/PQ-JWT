# Changelog

## 1.1.0 — 2026-05-16

### Fixed

- Add `types` condition to `package.json` `exports` for TypeScript 5+ / NodeNext resolution
- Explicitly include `src/index.d.ts` in published package files

## 1.0.0 — 2025-05-16

### Initial Release

- ML-DSA-44, ML-DSA-65, ML-DSA-87 (NIST FIPS 204)
- SLH-DSA-SHA2-128s (NIST FIPS 205)
- sign(), verify(), decode(), refresh()
- generateKeyPair(), exportKey(), importKey()
- algorithmInfo()
- Full typed error hierarchy
- 35/35 tests passing
