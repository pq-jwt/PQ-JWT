/**
 * @package     @pq-jwt/core
 * @author      Sachin Ruhil <sachinruhil11@gmail.com>
 * @version     1.1.1
 * @license     MIT
 * @description Post-quantum JWT library — NIST FIPS 204 (ML-DSA) + FIPS 205 (SLH-DSA)
 * @copyright   2025 Sachin Ruhil. All rights reserved.
 * @see         https://github.com/pq-jwt/PQ-JWT
 */

import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { slh_dsa_sha2_128s } from "@noble/post-quantum/slh-dsa.js";
import { sha512 } from "@noble/hashes/sha2.js";

const ALGORITHMS = {
  "ML-DSA-44": {
    impl: ml_dsa44,
    desc: "NIST FIPS 204, lattice-based, security level 2 (128-bit quantum)",
    pkLen: 1312,
    skLen: 2560,
    sigLen: 2420,
  },
  "ML-DSA-65": {
    impl: ml_dsa65,
    desc: "NIST FIPS 204, lattice-based, security level 3 (192-bit quantum)",
    pkLen: 1952,
    skLen: 4032,
    sigLen: 3293,
  },
  "ML-DSA-87": {
    impl: ml_dsa87,
    desc: "NIST FIPS 204, lattice-based, security level 5 (256-bit quantum)",
    pkLen: 2592,
    skLen: 4896,
    sigLen: 4595,
  },
  "SLH-DSA-SHA2-128s": {
    impl: slh_dsa_sha2_128s,
    desc: "NIST FIPS 205, hash-based, 128-bit quantum security",
    pkLen: 32,
    skLen: 64,
    sigLen: 7856,
  },
};

export const SUPPORTED_ALGORITHMS = Object.keys(ALGORITHMS);

/* ── Custom errors ── */
export class PQJWTError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "PQJWTError";
    this.code = code;
  }
}
export class TokenExpiredError extends PQJWTError {
  constructor(expiredAt) {
    super(
      `Token expired at ${new Date(expiredAt * 1000).toISOString()}`,
      "TOKEN_EXPIRED",
    );
    this.name = "TokenExpiredError";
    this.expiredAt = expiredAt;
  }
}
export class InvalidTokenError extends PQJWTError {
  constructor(reason) {
    super(`Invalid token: ${reason}`, "INVALID_TOKEN");
    this.name = "InvalidTokenError";
  }
}
export class SignatureError extends PQJWTError {
  constructor() {
    super("Signature verification failed", "SIGNATURE_INVALID");
    this.name = "SignatureError";
  }
}

/* ── Encoding utilities ── */
const enc = new TextEncoder();
const dec = new TextDecoder();

function toBase64Url(bytes) {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
function fromBase64Url(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4;
  return new Uint8Array(
    Buffer.from(pad ? padded + "=".repeat(4 - pad) : padded, "base64"),
  );
}
function encodeJSON(obj) {
  return toBase64Url(enc.encode(JSON.stringify(obj)));
}
function decodeJSON(str) {
  return JSON.parse(dec.decode(fromBase64Url(str)));
}

/* ── Key utilities ── */
export function exportKey(key) {
  if (!(key instanceof Uint8Array))
    throw new PQJWTError("exportKey expects Uint8Array", "INVALID_KEY");
  return Buffer.from(key).toString("hex");
}
export function importKey(hexString) {
  if (typeof hexString !== "string" || !/^[0-9a-f]+$/i.test(hexString))
    throw new PQJWTError("importKey expects hex string", "INVALID_KEY");
  return new Uint8Array(Buffer.from(hexString, "hex"));
}

export function generateKeyPair(algorithm = "ML-DSA-65") {
  const alg = ALGORITHMS[algorithm];
  if (!alg)
    throw new PQJWTError(
      `Unknown algorithm "${algorithm}". Supported: ${SUPPORTED_ALGORITHMS.join(", ")}`,
      "UNKNOWN_ALGORITHM",
    );
  const kp = alg.impl.keygen();
  return { publicKey: kp.publicKey, secretKey: kp.secretKey, algorithm };
}

/* ── Duration parser ── */
function parseDuration(duration) {
  if (typeof duration === "number") return duration;
  const match = String(duration).match(/^(\d+(?:\.\d+)?)(s|m|h|d|w)$/);
  if (!match)
    throw new PQJWTError(
      `Invalid duration "${duration}". Use number (seconds) or "1h","7d","30m".`,
      "INVALID_DURATION",
    );
  const value = parseFloat(match[1]);
  const unit = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 }[match[2]];
  return Math.floor(value * unit);
}

/* ── sign() ── */
export function sign(payload, secretKey, options = {}) {
  if (typeof payload !== "object" || payload === null)
    throw new PQJWTError("Payload must be non-null object", "INVALID_PAYLOAD");

  const algorithm = options.algorithm ?? "ML-DSA-65";
  const alg = ALGORITHMS[algorithm];
  if (!alg)
    throw new PQJWTError(
      `Unknown algorithm "${algorithm}"`,
      "UNKNOWN_ALGORITHM",
    );

  const sk = typeof secretKey === "string" ? importKey(secretKey) : secretKey;
  if (!(sk instanceof Uint8Array) || sk.length !== alg.skLen)
    throw new PQJWTError(
      `Secret key must be ${alg.skLen} bytes for ${algorithm}`,
      "INVALID_KEY",
    );

  const header = { alg: algorithm, typ: "PQ-JWT", ver: "1" };
  const now = Math.floor(Date.now() / 1000);
  const claims = { iat: now, ...payload };

  if (options.expiresIn !== undefined)
    claims.exp = now + parseDuration(options.expiresIn);
  if (options.issuer) claims.iss = options.issuer;
  if (options.subject) claims.sub = options.subject;
  if (options.audience) claims.aud = options.audience;
  if (options.jwtId) claims.jti = options.jwtId;

  const headerEncoded = encodeJSON(header);
  const payloadEncoded = encodeJSON(claims);
  const signingInput = enc.encode(`${headerEncoded}.${payloadEncoded}`);
  const digest = sha512(signingInput);
  const signature = alg.impl.sign(digest, sk);

  return `${headerEncoded}.${payloadEncoded}.${toBase64Url(signature)}`;
}

/* ── verify() ── */
export function verify(token, publicKey, options = {}) {
  if (typeof token !== "string")
    throw new InvalidTokenError("token must be a string");

  const parts = token.split(".");
  if (parts.length !== 3)
    throw new InvalidTokenError("token must have 3 dot-separated parts");

  const [headerEncoded, payloadEncoded, signatureEncoded] = parts;

  let header;
  try {
    header = decodeJSON(headerEncoded);
  } catch {
    throw new InvalidTokenError("header is not valid base64url JSON");
  }

  if (header.typ !== "PQ-JWT")
    throw new InvalidTokenError(`expected typ "PQ-JWT", got "${header.typ}"`);

  const algorithm = header.alg;
  const alg = ALGORITHMS[algorithm];
  if (!alg)
    throw new InvalidTokenError(`unrecognized algorithm "${algorithm}"`);

  if (options.algorithms) {
    const allowed = Array.isArray(options.algorithms)
      ? options.algorithms
      : [options.algorithms];
    if (!allowed.includes(algorithm))
      throw new InvalidTokenError(
        `algorithm "${algorithm}" not in allowed list`,
      );
  }

  const pk = typeof publicKey === "string" ? importKey(publicKey) : publicKey;
  if (!(pk instanceof Uint8Array) || pk.length !== alg.pkLen)
    throw new PQJWTError(
      `Public key must be ${alg.pkLen} bytes for ${algorithm}`,
      "INVALID_KEY",
    );

  let payload;
  try {
    payload = decodeJSON(payloadEncoded);
  } catch {
    throw new InvalidTokenError("payload is not valid base64url JSON");
  }

  const signingInput = enc.encode(`${headerEncoded}.${payloadEncoded}`);
  const digest = sha512(signingInput);
  const signature = fromBase64Url(signatureEncoded);

  let valid;
  try {
    valid = alg.impl.verify(signature, digest, pk);
  } catch {
    valid = false;
  }
  if (!valid) throw new SignatureError();

  const now = Math.floor(Date.now() / 1000);

  if (!options.ignoreExpiry && payload.exp !== undefined)
    if (now > payload.exp) throw new TokenExpiredError(payload.exp);

  if (payload.nbf !== undefined && now < payload.nbf)
    throw new PQJWTError(
      `Token not valid before ${new Date(payload.nbf * 1000).toISOString()}`,
      "TOKEN_NOT_YET_VALID",
    );

  if (options.issuer && payload.iss !== options.issuer)
    throw new InvalidTokenError(
      `issuer mismatch: expected "${options.issuer}", got "${payload.iss}"`,
    );
  if (options.audience) {
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(options.audience))
      throw new InvalidTokenError("audience mismatch");
  }
  if (options.subject && payload.sub !== options.subject)
    throw new InvalidTokenError("subject mismatch");

  return { header, payload };
}

/* ── decode() — no verification ── */
export function decode(token) {
  if (typeof token !== "string")
    throw new InvalidTokenError("token must be a string");
  const parts = token.split(".");
  if (parts.length !== 3)
    throw new InvalidTokenError("token must have 3 dot-separated parts");
  return {
    header: decodeJSON(parts[0]),
    payload: decodeJSON(parts[1]),
    signature: fromBase64Url(parts[2]),
  };
}

/* ── refresh() ── */
export function refresh(token, publicKey, secretKey, options = {}) {
  const { payload } = verify(token, publicKey, options);
  const { iat, exp, nbf, ...claims } = payload;
  return sign(claims, secretKey, options);
}

/* ── algorithmInfo() ── */
export function algorithmInfo(algorithm) {
  const alg = ALGORITHMS[algorithm];
  if (!alg)
    throw new PQJWTError(
      `Unknown algorithm "${algorithm}"`,
      "UNKNOWN_ALGORITHM",
    );
  return {
    algorithm,
    description: alg.desc,
    publicKeyBytes: alg.pkLen,
    secretKeyBytes: alg.skLen,
    signatureBytes: alg.sigLen,
    nistStandard: algorithm.startsWith("ML-DSA") ? "FIPS 204" : "FIPS 205",
  };
}
