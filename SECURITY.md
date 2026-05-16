# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.x     | ✅ Yes    |

## Reporting a vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Email: sachinruhil11@gmail.com

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact

You will receive a response within 72 hours.
We will credit researchers in the release notes.

## Cryptographic foundation

@pq-jwt/core uses @noble/post-quantum (audited) implementing
NIST FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA).
We do not implement our own cryptographic primitives.
