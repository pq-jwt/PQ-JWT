import { generateKeyPair, sign, verify, refresh } from '../src/index.mjs';

async function run() {
  console.log('--- Sliding Session / Refresh Flow Example ---');
  const { publicKey, secretKey } = generateKeyPair('ML-DSA-65');

  // 1. User logs in, issue short-lived token
  console.log('\n1. Issuing initial token (expires in 5m)');
  const oldToken = sign({ sessionId: 'abc-123' }, secretKey, { expiresIn: '5m' });
  const oldDecoded = verify(oldToken, publicKey);
  console.log('Initial iat:', oldDecoded.payload.iat);
  console.log('Initial exp:', oldDecoded.payload.exp);

  // simulate time passing
  await new Promise(r => setTimeout(r, 1000));

  // 2. User is still active, refresh the token for another 5m
  console.log('\n2. Refreshing token...');
  const newToken = refresh(oldToken, publicKey, secretKey, { expiresIn: '5m' });
  const newDecoded = verify(newToken, publicKey);
  console.log('New iat:', newDecoded.payload.iat);
  console.log('New exp:', newDecoded.payload.exp);

  console.log('\nTokens are different because iat/exp were updated and signature recomputed.');
  console.log('Check passed:', oldToken !== newToken);
}

run().catch(console.error);
