import crypto from 'node:crypto';
import { DEFAULT_KASHCASH_PUBLIC_KEY_PEM } from '../config/env.js';

const AES_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH_BYTES = 12;
const AUTH_TAG_LENGTH_BYTES = 16;

export interface KashCashSignatureInput {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  pathAndQuery: string;
  rawBody: string;
  signatureBase64: string | undefined;
  publicKeyPem?: string;
}

/**
 * Builds the exact JSON payload signed by KashCash's ECommerceBackChannel RequestSigningHandler
 * and verified by WooCommerce's WC_Kashcash_Payment_Gateway::is_verified():
 * {"Method":"...","PathAndQuery":"...","Body":"..."}
 */
export function buildKashCashSignedPayload(
  method: string,
  pathAndQuery: string,
  rawBody: string
): string {
  const payloadObj = {
    Method: method.toUpperCase(),
    PathAndQuery: pathAndQuery,
    Body: rawBody.trim(),
  };
  return JSON.stringify(payloadObj);
}

/**
 * Verifies the `x-signature` header sent by KashCash ECommerceBackChannel using RSA-SHA512.
 */
export function verifyKashCashSignature(input: KashCashSignatureInput): boolean {
  const {
    method,
    pathAndQuery,
    rawBody,
    signatureBase64,
    publicKeyPem = DEFAULT_KASHCASH_PUBLIC_KEY_PEM,
  } = input;

  if (!signatureBase64 || typeof signatureBase64 !== 'string' || signatureBase64.trim() === '') {
    return false;
  }

  try {
    const trimmedSig = signatureBase64.trim();
    // Validate strict base64 format
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmedSig) || trimmedSig.length % 4 !== 0) {
      return false;
    }

    const signatureBuffer = Buffer.from(trimmedSig, 'base64');
    if (signatureBuffer.length === 0) {
      return false;
    }

    const dataSigned = buildKashCashSignedPayload(method, pathAndQuery, rawBody);
    return crypto.verify(
      'RSA-SHA512',
      Buffer.from(dataSigned, 'utf8'),
      publicKeyPem,
      signatureBuffer
    );
  } catch {
    return false;
  }
}

/**
 * Signs a request payload with an RSA private key using RSA-SHA512 (matches cashi-server RequestSigningHandler).
 */
export function signKashCashPayload(
  method: string,
  pathAndQuery: string,
  rawBody: string,
  privateKeyPem: string
): string {
  const dataSigned = buildKashCashSignedPayload(method, pathAndQuery, rawBody);
  const signature = crypto.sign('RSA-SHA512', Buffer.from(dataSigned, 'utf8'), privateKeyPem);
  return signature.toString('base64');
}

/**
 * Encrypts sensitive credentials (MerchantToken, Shopify AccessToken) at rest using AES-256-GCM.
 * Output format: `v1:<iv_hex>:<authTag_hex>:<ciphertext_hex>`
 */
export function encryptSecret(plaintext: string, hexKey: string): string {
  if (!plaintext) {
    throw new Error('Cannot encrypt empty secret');
  }
  const key = Buffer.from(hexKey, 'hex');
  if (key.length !== 32) {
    throw new Error('Encryption key must be 32 bytes (64 hex characters)');
  }

  const iv = crypto.randomBytes(IV_LENGTH_BYTES);
  const cipher = crypto.createCipheriv(AES_ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH_BYTES,
  });

  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return `v1:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * Decrypts a secret encrypted by `encryptSecret`.
 */
export function decryptSecret(encryptedPayload: string, hexKey: string): string {
  const key = Buffer.from(hexKey, 'hex');
  if (key.length !== 32) {
    throw new Error('Encryption key must be 32 bytes (64 hex characters)');
  }

  const parts = encryptedPayload.split(':');
  if (parts.length !== 4 || parts[0] !== 'v1') {
    throw new Error('Invalid encrypted secret format');
  }

  const [, ivHex, authTagHex, ciphertextHex] = parts;
  if (!ivHex || !authTagHex || ciphertextHex === undefined) {
    throw new Error('Malformed encrypted secret segments');
  }

  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const ciphertext = Buffer.from(ciphertextHex, 'hex');

  if (iv.length !== IV_LENGTH_BYTES || authTag.length !== AUTH_TAG_LENGTH_BYTES) {
    throw new Error('Invalid IV or AuthTag length');
  }

  const decipher = crypto.createDecipheriv(AES_ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH_BYTES,
  });
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}

/**
 * Constant-time string comparison to prevent timing side-channel attacks.
 */
export function timingSafeStringEqual(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Verifies Shopify Webhook HMAC-SHA256 header (`X-Shopify-Hmac-Sha256`) over the raw request body.
 */
export function verifyShopifyWebhookHmac(
  rawBody: Buffer | string,
  hmacHeader: string | undefined,
  shopifyApiSecret: string
): boolean {
  if (!hmacHeader || !shopifyApiSecret) {
    return false;
  }
  const computedBase64 = crypto
    .createHmac('sha256', shopifyApiSecret)
    .update(rawBody)
    .digest('base64');

  return timingSafeStringEqual(computedBase64, hmacHeader.trim());
}

/**
 * Verifies Shopify OAuth callback query parameters HMAC-SHA256.
 */
export function verifyShopifyOAuthHmac(
  query: Record<string, string | string[] | undefined>,
  shopifyApiSecret: string
): boolean {
  const providedHmac = typeof query.hmac === 'string' ? query.hmac : undefined;
  if (!providedHmac || !shopifyApiSecret) {
    return false;
  }

  const message = Object.keys(query)
    .filter((key) => key !== 'hmac' && key !== 'signature' && query[key] !== undefined)
    .sort()
    .map((key) => {
      const val = query[key];
      const serializedVal = Array.isArray(val) ? val.join(',') : String(val);
      return `${key}=${serializedVal}`;
    })
    .join('&');

  const computedHex = crypto
    .createHmac('sha256', shopifyApiSecret)
    .update(message, 'utf8')
    .digest('hex');

  return timingSafeStringEqual(computedHex, providedHmac.toLowerCase());
}

/**
 * Validates that a shop domain strictly matches `<subdomain>.myshopify.com` to prevent SSRF.
 */
export function isValidShopDomain(shop: string | undefined): shop is string {
  if (!shop || typeof shop !== 'string') {
    return false;
  }
  return /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}\.myshopify\.com$/.test(shop);
}

/**
 * Generates a cryptographically random token for order_key / OAuth state.
 */
export function generateSecureToken(prefix = 'kc', byteLength = 24): string {
  return `${prefix}_${crypto.randomBytes(byteLength).toString('hex')}`;
}
