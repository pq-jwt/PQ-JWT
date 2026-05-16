/**
 * @package     @pq-jwt/core
 * @author      Sachin Ruhil <sachinruhil11@gmail.com>
 * @version     1.1.1
 * @license     MIT
 * @description Post-quantum JWT library — NIST FIPS 204 (ML-DSA) + FIPS 205 (SLH-DSA)
 * @copyright   2025 Sachin Ruhil. All rights reserved.
 * @see         https://github.com/pq-jwt/PQ-JWT
 */

export type Algorithm = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87' | 'SLH-DSA-SHA2-128s';

export const SUPPORTED_ALGORITHMS: Algorithm[];

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  algorithm: Algorithm;
}

export interface SignOptions {
  algorithm?: Algorithm;
  expiresIn?: number | string;
  issuer?: string;
  subject?: string;
  audience?: string;
  jwtId?: string;
}

export interface VerifyOptions {
  algorithms?: Algorithm | Algorithm[];
  issuer?: string;
  audience?: string;
  subject?: string;
  ignoreExpiry?: boolean;
}

export interface DecodedToken {
  header: {
    alg: string;
    typ: string;
    ver: string;
    [key: string]: any;
  };
  payload: {
    [key: string]: any;
  };
  signature: Uint8Array;
}

export class PQJWTError extends Error {
  code: string;
  constructor(message: string, code: string);
}

export class TokenExpiredError extends PQJWTError {
  expiredAt: number;
  constructor(expiredAt: number);
}

export class InvalidTokenError extends PQJWTError {
  constructor(reason: string);
}

export class SignatureError extends PQJWTError {
  constructor();
}

export function exportKey(key: Uint8Array): string;
export function importKey(hexString: string): Uint8Array;
export function generateKeyPair(algorithm?: Algorithm): KeyPair;
export function sign(payload: object, secretKey: Uint8Array | string, options?: SignOptions): string;
export function verify(token: string, publicKey: Uint8Array | string, options?: VerifyOptions): { header: any, payload: any };
export function decode(token: string): DecodedToken;
export function refresh(token: string, publicKey: Uint8Array | string, secretKey: Uint8Array | string, options?: SignOptions & VerifyOptions): string;
export function algorithmInfo(algorithm: Algorithm): {
  algorithm: string;
  description: string;
  publicKeyBytes: number;
  secretKeyBytes: number;
  signatureBytes: number;
  nistStandard: string;
};
