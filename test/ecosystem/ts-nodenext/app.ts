import {
  generateKeyPair,
  sign,
  verify,
  type Algorithm,
  type SignOptions,
} from '@pq-jwt/core';

const alg: Algorithm = 'ML-DSA-65';
const options: SignOptions = { expiresIn: '60s', issuer: 'ecosystem-test' };

const { publicKey, secretKey } = generateKeyPair(alg);
const token = sign({ runtime: 'typescript-nodenext' }, secretKey, options);
const { payload } = verify(token, publicKey, { issuer: 'ecosystem-test' });

if (payload.runtime !== 'typescript-nodenext') {
  throw new Error('TypeScript NodeNext consumer: verify payload mismatch');
}

console.log('OK typescript/nodenext');
