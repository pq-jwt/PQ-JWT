import { generateKeyPair, sign, verify } from '../src/index.mjs';

async function run() {
  console.log('Generating keys...');
  const { publicKey, secretKey } = generateKeyPair('ML-DSA-65');

  console.log('Signing payload...');
  const payload = { userId: 123, role: 'admin' };
  const token = sign(payload, secretKey, { expiresIn: '1h', issuer: 'my-app' });

  console.log('Token:', token);

  console.log('\nVerifying token...');
  const decoded = verify(token, publicKey, { issuer: 'my-app' });
  console.log('Decoded Payload:', decoded.payload);
}

run().catch(console.error);
