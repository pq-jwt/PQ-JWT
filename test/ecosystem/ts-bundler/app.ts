import { generateKeyPair, sign, verify, type Algorithm } from '@pq-jwt/core';

const alg: Algorithm = 'ML-DSA-44';
const { publicKey, secretKey } = generateKeyPair(alg);
const token = sign({ runtime: 'typescript-bundler' }, secretKey);
const { payload } = verify(token, publicKey);

if (payload.runtime !== 'typescript-bundler') {
  throw new Error('TypeScript Bundler consumer: verify payload mismatch');
}

console.log('OK typescript/bundler');
