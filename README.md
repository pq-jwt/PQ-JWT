# PQ-JWT - Post-Quantum JWT Node.js Library

[![CI](https://github.com/ruhil6789/pq-jwt/actions/workflows/ci.yml/badge.svg)](https://github.com/ruhil6789/pq-jwt/actions/workflows/ci.yml)

A comprehensive, production-ready JavaScript/Node.js library for generating, managing, signing, and verifying **Post-Quantum Cryptography (PQC) JSON Web Tokens (JWTs)**. It acts as a drop-in successor to broken RS256/ES256 libraries.

This library provides quantum-resistant JWT authentication using pure Javascript implementations of NIST-standardized algorithms via the highly audited `@noble/post-quantum` package.

---

## Features

- **Zero Native Dependencies**: Uses pure JS math, running seamlessly in Node.js >= 16 without complex C++ bindings.
- **Post-Quantum Ready**: Implements NIST-standardized ML-DSA (Dilithium) and SLH‑DSA (SPHINCS+) signature algorithms.
- **Familiar API**: Syntax identical to classic JWT libraries (`sign()`, `verify()`, `decode()`, `refresh()`).
- **Standard JWT Claims**: Automatic validation of `exp` (with duration strings like `'1h'`), `nbf`, `iss`, `sub`, and `aud`.
- **Comprehensive Error Handling**: Typed exceptions (`TokenExpiredError`, `SignatureError`, `InvalidTokenError`).
- **Key Serialization**: Export and import keys effortlessly via fast hex encoding.
- **TypeScript Support**: Full `.d.ts` types included out of the box.

---

## Requirements

- Node.js 16.0.0 or higher

---

## Installation

### npm

```bash
npm install @pq-jwt/core
```

### yarn

```bash
yarn add @pq-jwt/core
```

### pnpm

```bash
pnpm add @pq-jwt/core
```

---

## Quick Start

### Basic Sign & Verify

```javascript
import { generateKeyPair, sign, verify } from "@pq-jwt/core";

// 1. Generate keys (uses ML-DSA-65 by default)
const { publicKey, secretKey } = generateKeyPair("ML-DSA-65");

// 2. Sign a JWT payload
const jwtToken = sign({ userId: 123, role: "admin" }, secretKey, {
  expiresIn: "1h",
  issuer: "my-app",
});
console.log("Generated JWT:", jwtToken);

// 3. Verify the token
try {
  const decoded = verify(jwtToken, publicKey, { issuer: "my-app" });
  console.log("JWT is valid!");
  console.log("Payload:", decoded.payload);
} catch (error) {
  console.log("Verification failed:", error.message);
}
```

### Token Refresh (Sliding Sessions)

```javascript
import { refresh } from "@pq-jwt/core";

// Automatically verifies the old token, bumps the iat and exp, and resigns
const newToken = refresh(oldToken, publicKey, secretKey, { expiresIn: "1h" });
```

---

## Supported Algorithms

### ML-DSA (Dilithium) - NIST FIPS 204

| Algorithm | Security Level | Quantum Security | Description                    |
| --------- | -------------- | ---------------- | ------------------------------ |
| ML-DSA-44 | Level 2        | 64-bit Q         | IoT / constrained environments |
| ML-DSA-65 | Level 3        | 96-bit Q         | General use (DEFAULT)          |
| ML-DSA-87 | Level 5        | 128-bit Q        | High security / Government     |

### SLH‑DSA (SPHINCS+) - NIST FIPS 205

| Algorithm         | Security Level | Quantum Security | Description             |
| ----------------- | -------------- | ---------------- | ----------------------- |
| SLH-DSA-SHA2-128s | Level 1        | 64-bit Q         | Conservative / Archival |

_Note: SPHINCS+ produces much larger signatures and is slower to compute, but relies on conservative hash-based assumptions rather than lattice cryptography._

---

## Key Management & Environment Variables (.env)

One of the biggest confusions for developers switching to Post-Quantum JWTs is how to handle the massive keys. Classic JWTs (like `HS256`) use a simple text password (e.g., `JWT_SECRET="my-super-secret"`) that you can easily put in your `.env` file.

Because ML-DSA and SLH-DSA use **asymmetric cryptography**, their keys are massive, mathematically-linked byte arrays (often 4KB+). You **cannot** generate these keys dynamically every time your server starts, or all previously issued tokens will instantly become invalid.

**You handle this by generating the keys ONCE, converting them to hex, and placing them in your `.env` file!**

### Step 1: One-Time Setup Script

Run this script locally on your machine just once to generate your public and private keys, and encode them into pure strings using `exportKey`.

```javascript
// one-time-setup.mjs
import { generateKeyPair, exportKey } from "@pq-jwt/core";

// Generate keys once
const { publicKey, secretKey } = generateKeyPair("ML-DSA-65");

// Convert huge byte arrays to safe hexadecimal strings
console.log("--- ADD THESE TO YOUR .env FILE ---");
console.log(`PQ_PRIVATE_KEY="${exportKey(secretKey)}"`);
console.log(`PQ_PUBLIC_KEY="${exportKey(publicKey)}"`);
```

### Step 2: Production Server

In your production app (like Express or Next.js), you simply read those strings from your `.env` file and convert them back into crypto-ready keys using `importKey`. This makes your workflow absolutely identical to classic JWTs!

```javascript
// server.mjs
import { importKey, sign, verify } from "@pq-jwt/core";

// 1. Load keys securely from Environment Variables!
const secretKey = importKey(process.env.PQ_PRIVATE_KEY);
const publicKey = importKey(process.env.PQ_PUBLIC_KEY);

// 2. Sign and Verify normally!
const token = sign({ userId: 123 }, secretKey, { expiresIn: "1h" });
const payload = verify(token, publicKey);
```

This pattern perfectly separates your key generation from your application lifecycle, ensuring your server remains stateless and infinitely scalable.

---

## Error Handling

The library uses a typed error hierarchy, allowing you to catch specific scenarios:

- `TokenExpiredError` – Token has passed its `exp` time
- `SignatureError` – Signature validation completely failed (preventing tampering)
- `InvalidTokenError` – Token is malformed or claim validation failed (wrong issuer, audience, etc.)
- `PQJWTError` – Base class for cryptographical misconfigurations (e.g., wrong key size)

```javascript
import { TokenExpiredError, SignatureError, verify } from "@pq-jwt/core";

try {
  verify(token, publicKey);
} catch (error) {
  if (error instanceof TokenExpiredError) {
    console.log(`Token expired cleanly at ${error.expiredAt}`);
  } else if (error instanceof SignatureError) {
    console.log("CRITICAL: Token was tampered with!");
  }
}
```

---

## Architecture Context

Unlike purely file-bound implementations, `@pq-jwt/core` is stateless and decoupled from the file system. You manage where the keys are stored, granting you full flexibility over databases, secret managers, or standard environment variables (`process.env.PQ_PRIVATE_KEY`).

---

## Performance Overview

_Verified Benchmarks (ML-DSA-65):_

- **Sign**: ~11.1ms
- **Verify**: ~3.9ms
- **Token Size**: ~4.5KB

---

## License

MIT License - see [LICENSE](./LICENSE)
