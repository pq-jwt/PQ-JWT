import { generateKeyPair, sign, verify } from '../src/index.mjs';

// 1. Generate keys for the server
const { publicKey, secretKey } = generateKeyPair('ML-DSA-65');

// 2. The Express middleware function
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = verify(token, publicKey);
    req.user = decoded.payload; // Attach payload to request
    next(); // Proceed to route handler
  } catch (error) {
    return res.status(401).json({ error: error.message });
  }
}

// 3. Runnable simulation (mocking Express req/res)
console.log('--- Express Middleware Example Run ---');
const validToken = sign({ userId: 42, role: 'user' }, secretKey, { expiresIn: '15m' });

// Mock successful request
console.log('\nTesting valid token:');
const req1 = { headers: { authorization: `Bearer ${validToken}` } };
const res1 = {
  status: (code) => ({
    json: (data) => console.log(`Response [${code}]:`, data)
  })
};
requireAuth(req1, res1, () => {
  console.log('Middleware next() called. User attached:', req1.user);
});

// Mock failed request (tampered token)
console.log('\nTesting tampered token:');
const req2 = { headers: { authorization: `Bearer ${validToken}tampered` } };
const res2 = {
  status: (code) => ({
    json: (data) => console.log(`Response [${code}]:`, data)
  })
};
requireAuth(req2, res2, () => {
  console.log('This should not be called!');
});
