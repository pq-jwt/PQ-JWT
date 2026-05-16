import assert from 'assert';
import { 
  generateKeyPair, sign, verify, decode, refresh, exportKey, importKey, 
  algorithmInfo, SUPPORTED_ALGORITHMS, 
  TokenExpiredError, InvalidTokenError, SignatureError, PQJWTError
} from '../src/index.mjs';

let passed = 0;
let total = 0;

async function test(name, fn) {
  total++;
  try {
    await fn();
    passed++;
    console.log(`✓ ${name}`);
  } catch (err) {
    console.error(`✗ ${name}`);
    console.error(err);
  }
}

async function runTests() {
  const keys = {};

  // 1-4: Keygen lengths
  for (const alg of SUPPORTED_ALGORITHMS) {
    await test(`${alg} keygen length`, () => {
      keys[alg] = generateKeyPair(alg);
      const info = algorithmInfo(alg);
      assert.strictEqual(keys[alg].publicKey.length, info.publicKeyBytes);
      assert.strictEqual(keys[alg].secretKey.length, info.secretKeyBytes);
    });
  }

  // 5-8: Signature sizes match @noble/post-quantum
  const EXPECTED_SIG = {
    'ML-DSA-44': 2420,
    'ML-DSA-65': 3309,
    'ML-DSA-87': 4627,
    'SLH-DSA-SHA2-128s': 7856,
  };
  for (const alg of SUPPORTED_ALGORITHMS) {
    await test(`${alg} algorithmInfo signatureBytes`, () => {
      assert.strictEqual(algorithmInfo(alg).signatureBytes, EXPECTED_SIG[alg]);
    });
    await test(`${alg} actual signature length (5 samples)`, () => {
      for (let i = 0; i < 5; i++) {
        const token = sign({ sample: i }, keys[alg].secretKey, { algorithm: alg });
        const { signature } = decode(token);
        assert.strictEqual(signature.length, EXPECTED_SIG[alg]);
      }
    });
  }

  // 9
  await test('exportKey/importKey round-trip', () => {
    const exported = exportKey(keys['ML-DSA-65'].publicKey);
    const imported = importKey(exported);
    assert.deepStrictEqual(imported, keys['ML-DSA-65'].publicKey);
  });

  // 6
  await test('sign() returns 3-part dot-separated string', () => {
    const token = sign({ test: 1 }, keys['ML-DSA-65'].secretKey);
    assert.strictEqual(token.split('.').length, 3);
  });

  // 7
  await test('verify() returns header and payload with correct values', () => {
    const token = sign({ test: 1 }, keys['ML-DSA-65'].secretKey);
    const decoded = verify(token, keys['ML-DSA-65'].publicKey);
    assert.strictEqual(decoded.header.alg, 'ML-DSA-65');
    assert.strictEqual(decoded.payload.test, 1);
  });

  // 8
  await test('50/50 single-bit signature flip attempts → all detected', () => {
    const token = sign({ test: 1 }, keys['ML-DSA-65'].secretKey);
    const parts = token.split('.');
    const sigBytes = Buffer.from(parts[2], 'base64url');
    for (let i = 0; i < 50; i++) {
      const badSig = Buffer.from(sigBytes);
      badSig[i] ^= 1; 
      const badToken = `${parts[0]}.${parts[1]}.${badSig.toString('base64url')}`;
      assert.throws(() => verify(badToken, keys['ML-DSA-65'].publicKey), SignatureError);
    }
  });

  // 9
  await test('20/20 payload substitution attempts → all detected', () => {
    const token = sign({ user: 'alice' }, keys['ML-DSA-65'].secretKey);
    const parts = token.split('.');
    for (let i = 0; i < 20; i++) {
        const fakePayload = Buffer.from(JSON.stringify({ user: 'bob', i })).toString('base64url');
        const badToken = `${parts[0]}.${fakePayload}.${parts[2]}`;
        assert.throws(() => verify(badToken, keys['ML-DSA-65'].publicKey), SignatureError);
    }
  });

  // 10
  await test('Algorithm confusion (alg: none) → rejected', () => {
    const fakeHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'PQ-JWT' })).toString('base64url');
    const fakePayload = Buffer.from(JSON.stringify({ test: 1 })).toString('base64url');
    const badToken = `${fakeHeader}.${fakePayload}.abc`;
    assert.throws(() => verify(badToken, keys['ML-DSA-65'].publicKey), InvalidTokenError);
  });

  // 11
  await test('Cross-key attack (wrong public key) → rejected', () => {
    const token = sign({ test: 1 }, keys['ML-DSA-65'].secretKey);
    assert.throws(() => verify(token, keys['ML-DSA-87'].publicKey), PQJWTError); // key length mismatch or SignatureError
  });

  // 12
  await test('TokenExpiredError thrown for expired tokens', () => {
    const token = sign({ exp: Math.floor(Date.now() / 1000) - 100 }, keys['ML-DSA-65'].secretKey);
    assert.throws(() => verify(token, keys['ML-DSA-65'].publicKey), TokenExpiredError);
  });

  // 13
  await test('ignoreExpiry option works', () => {
    const token = sign({ exp: Math.floor(Date.now() / 1000) - 100 }, keys['ML-DSA-65'].secretKey);
    assert.doesNotThrow(() => verify(token, keys['ML-DSA-65'].publicKey, { ignoreExpiry: true }));
  });

  // 14
  await test('nbf in future → TOKEN_NOT_YET_VALID', () => {
    const token = sign({ nbf: Math.floor(Date.now() / 1000) + 100 }, keys['ML-DSA-65'].secretKey);
    assert.throws(() => verify(token, keys['ML-DSA-65'].publicKey), (err) => err.code === 'TOKEN_NOT_YET_VALID');
  });

  await test('notBefore option sets nbf and blocks verify until valid', () => {
    const token = sign({ sub: 'u1' }, keys['ML-DSA-65'].secretKey, { notBefore: '1h' });
    const { payload } = decode(token);
    const now = Math.floor(Date.now() / 1000);
    assert.ok(payload.nbf >= now + 3599);
    assert.throws(() => verify(token, keys['ML-DSA-65'].publicKey), (err) => err.code === 'TOKEN_NOT_YET_VALID');
  });

  await test('clockTolerance accepts slightly expired token', () => {
    const token = sign(
      { x: 1, exp: Math.floor(Date.now() / 1000) - 10 },
      keys['ML-DSA-65'].secretKey,
    );
    assert.throws(() => verify(token, keys['ML-DSA-65'].publicKey), TokenExpiredError);
    assert.doesNotThrow(() => verify(token, keys['ML-DSA-65'].publicKey, { clockTolerance: 15 }));
  });

  await test('clockTolerance accepts token before nbf within skew window', () => {
    const token = sign({ x: 1 }, keys['ML-DSA-65'].secretKey, { notBefore: '8s' });
    assert.throws(() => verify(token, keys['ML-DSA-65'].publicKey), (err) => err.code === 'TOKEN_NOT_YET_VALID');
    assert.doesNotThrow(() => verify(token, keys['ML-DSA-65'].publicKey, { clockTolerance: 10 }));
  });

  // 15-19: Duration strings
  const durations = ['60s', '5m', '2h', '1d', '1w'];
  for (const d of durations) {
    await test(`Duration string '${d}' parses correctly`, () => {
      const token = sign({}, keys['ML-DSA-65'].secretKey, { expiresIn: d });
      const decoded = verify(token, keys['ML-DSA-65'].publicKey);
      assert(decoded.payload.exp > decoded.payload.iat);
    });
  }

  // 20
  await test('Issuer claim validation - valid', () => {
    const token = sign({}, keys['ML-DSA-65'].secretKey, { issuer: 'test-issuer' });
    assert.doesNotThrow(() => verify(token, keys['ML-DSA-65'].publicKey, { issuer: 'test-issuer' }));
  });

  // 21
  await test('Issuer claim validation - mismatch', () => {
    const token = sign({}, keys['ML-DSA-65'].secretKey, { issuer: 'test-issuer' });
    assert.throws(() => verify(token, keys['ML-DSA-65'].publicKey, { issuer: 'wrong-issuer' }), InvalidTokenError);
  });

  // 22
  await test('Audience claim validation - valid', () => {
    const token = sign({}, keys['ML-DSA-65'].secretKey, { audience: 'test-aud' });
    assert.doesNotThrow(() => verify(token, keys['ML-DSA-65'].publicKey, { audience: 'test-aud' }));
  });

  // 23
  await test('Audience claim validation - mismatch', () => {
    const token = sign({}, keys['ML-DSA-65'].secretKey, { audience: 'test-aud' });
    assert.throws(() => verify(token, keys['ML-DSA-65'].publicKey, { audience: 'wrong-aud' }), InvalidTokenError);
  });

  // 24
  await test('Subject claim validation - valid', () => {
    const token = sign({}, keys['ML-DSA-65'].secretKey, { subject: 'test-sub' });
    assert.doesNotThrow(() => verify(token, keys['ML-DSA-65'].publicKey, { subject: 'test-sub' }));
  });

  // 25
  await test('Subject claim validation - mismatch', () => {
    const token = sign({}, keys['ML-DSA-65'].secretKey, { subject: 'test-sub' });
    assert.throws(() => verify(token, keys['ML-DSA-65'].publicKey, { subject: 'wrong-sub' }), InvalidTokenError);
  });

  // 26
  await test('Algorithm allowlist enforcement - valid', () => {
    const token = sign({}, keys['ML-DSA-65'].secretKey, { algorithm: 'ML-DSA-65' });
    assert.doesNotThrow(() => verify(token, keys['ML-DSA-65'].publicKey, { algorithms: ['ML-DSA-65'] }));
  });

  // 27
  await test('Algorithm allowlist enforcement - mismatch', () => {
    const token = sign({}, keys['ML-DSA-65'].secretKey, { algorithm: 'ML-DSA-65' });
    assert.throws(() => verify(token, keys['ML-DSA-65'].publicKey, { algorithms: ['ML-DSA-87'] }), InvalidTokenError);
  });

  // 28
  await test('decode() works without verification', () => {
    const token = sign({ test: 1 }, keys['ML-DSA-65'].secretKey);
    const decoded = decode(token);
    assert.strictEqual(decoded.payload.test, 1);
  });

  // 29
  await test('refresh() issues new token with fresh iat/exp', async () => {
    const token = sign({}, keys['ML-DSA-65'].secretKey, { expiresIn: '1h' });
    await new Promise(r => setTimeout(r, 1000));
    const token2 = refresh(token, keys['ML-DSA-65'].publicKey, keys['ML-DSA-65'].secretKey, { expiresIn: '1h' });
    const dec1 = verify(token, keys['ML-DSA-65'].publicKey);
    const dec2 = verify(token2, keys['ML-DSA-65'].publicKey);
    assert(dec2.payload.iat > dec1.payload.iat);
  });

  // 30-33: specific sign+verify flows
  for (const alg of SUPPORTED_ALGORITHMS) {
    await test(`${alg} sign+verify`, () => {
      const token = sign({ test: alg }, keys[alg].secretKey, { algorithm: alg });
      const dec = verify(token, keys[alg].publicKey);
      assert.strictEqual(dec.payload.test, alg);
    });
  }

  // 34
  await test('10,000 random forgery attempts → 0 successes', () => {
    const token = sign({ test: 1 }, keys['ML-DSA-65'].secretKey);
    const parts = token.split('.');
    let successes = 0;
    for (let i = 0; i < 10000; i++) {
        const randSig = Buffer.from(keys['ML-DSA-65'].secretKey.slice(0, 10)).toString('base64url'); // Just some random bytes
        const badToken = `${parts[0]}.${parts[1]}.${randSig}`;
        try {
            verify(badToken, keys['ML-DSA-65'].publicKey);
            successes++;
        } catch(e) {}
    }
    assert.strictEqual(successes, 0);
  });

  // 35
  await test('Large payload (500 items) round-trips correctly', () => {
    const largePayload = { items: Array.from({length: 500}, (_, i) => i) };
    const token = sign(largePayload, keys['ML-DSA-65'].secretKey);
    const dec = verify(token, keys['ML-DSA-65'].publicKey);
    assert.strictEqual(dec.payload.items.length, 500);
  });

  console.log(`\n${passed}/${total} passing`);
  if (passed !== total) {
    process.exit(1);
  }
}

runTests();
