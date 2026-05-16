# Contributing to @pq-jwt/core

Thank you for helping make post-quantum authentication
accessible to every developer.

## Before you start

- Open an issue first for any significant change
- All contributions must keep 35/35 tests passing
- Never implement your own cryptographic primitives
- Only use @noble/post-quantum and @noble/hashes underneath

## Setup

```bash
git clone https://github.com/pq-jwt/PQ-JWT
cd PQ-JWT
npm install
node test/test.mjs   # must show 35/35 passing
```

## Making a change

1. Fork the repo
2. Create a branch: `git checkout -b feat/your-feature`
3. Make your change
4. Run tests: `node test/test.mjs`
5. Open a Pull Request against `main`

## What we welcome

- TypeScript type definitions (`src/index.d.ts`)
- New algorithm support (must be NIST-standardized)
- Framework integrations (Express, Fastify, Hono)
- Performance improvements
- Documentation improvements
- Bug reports with reproduction steps

## What we do not accept

- Custom cryptographic implementations
- Algorithms not standardized by NIST
- Breaking changes to the public API without discussion

## Code style

- ESM only (.mjs)
- No build step required
- Keep dependencies minimal

## Author

Sachin Ruhil — sachinruhil11@gmail.com
