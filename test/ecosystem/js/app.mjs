import { generateKeyPair, sign, verify } from '@pq-jwt/core';

const { publicKey, secretKey } = generateKeyPair('ML-DSA-65');
const token = sign({ runtime: 'javascript' }, secretKey, { expiresIn: '60s' });
const { payload } = verify(token, publicKey);

if (payload.runtime !== 'javascript') {
  throw new Error('JavaScript consumer: verify payload mismatch');
}

console.log('OK javascript/esm');
