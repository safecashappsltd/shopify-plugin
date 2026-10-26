import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  buildKashCashSignedPayload,
  decryptSecret,
  encryptSecret,
  isValidShopDomain,
  signKashCashPayload,
  timingSafeStringEqual,
  verifyKashCashSignature,
  verifyShopifyOAuthHmac,
  verifyShopifyWebhookHmac,
} from '../src/security/crypto.js';

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const TEST_HEX_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

describe('Security & Cryptography Module', () => {
  describe('KashCash RSA-SHA512 Signature Verification', () => {
    it('verifies a valid GET order signature with empty body', () => {
      const pathAndQuery = '/wp-json/kashcash/v1/order/100001';
      const sig = signKashCashPayload('GET', pathAndQuery, '', privateKey);

      const isValid = verifyKashCashSignature({
        method: 'GET',
        pathAndQuery,
        rawBody: '',
        signatureBase64: sig,
        publicKeyPem: publicKey,
      });

      expect(isValid).toBe(true);
    });

    it('verifies a valid POST webhook signature with JSON body', () => {
      const pathAndQuery = '/wp-json/kashcash/v1/webhook/';
      const rawBody = JSON.stringify({
        orderId: '100001',
        status: 'approved',
        transactionId: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
      });
      const sig = signKashCashPayload('POST', pathAndQuery, rawBody, privateKey);

      expect(
        verifyKashCashSignature({
          method: 'POST',
          pathAndQuery,
          rawBody: `  ${rawBody}\n`,
          signatureBase64: sig,
          publicKeyPem: publicKey,
        })
      ).toBe(true);
    });

    it('rejects tampered body, wrong path, wrong method, and malformed signatures', () => {
      const pathAndQuery = '/wp-json/kashcash/v1/webhook/';
      const rawBody = '{"orderId":"100001","status":"approved"}';
      const sig = signKashCashPayload('POST', pathAndQuery, rawBody, privateKey);

      // Tampered body
      expect(
        verifyKashCashSignature({
          method: 'POST',
          pathAndQuery,
          rawBody: '{"orderId":"100001","status":"rejected"}',
          signatureBase64: sig,
          publicKeyPem: publicKey,
        })
      ).toBe(false);

      // Tampered path
      expect(
        verifyKashCashSignature({
          method: 'POST',
          pathAndQuery: '/wp-json/kashcash/v1/order/100001',
          rawBody,
          signatureBase64: sig,
          publicKeyPem: publicKey,
        })
      ).toBe(false);

      // Missing / empty / non-base64 signatures
      expect(
        verifyKashCashSignature({
          method: 'POST',
          pathAndQuery,
          rawBody,
          signatureBase64: undefined,
          publicKeyPem: publicKey,
        })
      ).toBe(false);

      expect(
        verifyKashCashSignature({
          method: 'POST',
          pathAndQuery,
          rawBody,
          signatureBase64: 'not-valid-base64!!!',
          publicKeyPem: publicKey,
        })
      ).toBe(false);
    });

    it('builds exact JSON structure expected by cashi-server RequestSigningHandler', () => {
      const payload = buildKashCashSignedPayload(
        'GET',
        '/wp-json/kashcash/v1/order/100001',
        '  '
      );
      expect(payload).toBe(
        '{"Method":"GET","PathAndQuery":"/wp-json/kashcash/v1/order/100001","Body":""}'
      );
    });
  });

  describe('AES-256-GCM Secret Encryption at Rest', () => {
    it('encrypts and decrypts secrets including Unicode / Hebrew text with unique IVs', () => {
      const secret = 'kc_live_token_שלום_1234567890';
      const encrypted1 = encryptSecret(secret, TEST_HEX_KEY);
      const encrypted2 = encryptSecret(secret, TEST_HEX_KEY);

      expect(encrypted1).not.toBe(encrypted2);
      expect(encrypted1.startsWith('v1:')).toBe(true);
      expect(decryptSecret(encrypted1, TEST_HEX_KEY)).toBe(secret);
      expect(decryptSecret(encrypted2, TEST_HEX_KEY)).toBe(secret);
    });

    it('throws when ciphertext or auth tag is tampered with', () => {
      const encrypted = encryptSecret('super-secret-merchant-token', TEST_HEX_KEY);
      const parts = encrypted.split(':');
      // Flip a byte in the authTag
      const tamperedTag =
        parts[2]!.slice(0, -2) + (parts[2]!.endsWith('ff') ? '00' : 'ff');
      const tampered = `${parts[0]}:${parts[1]}:${tamperedTag}:${parts[3]}`;

      expect(() => decryptSecret(tampered, TEST_HEX_KEY)).toThrow();
    });

    it('rejects empty secrets or invalid key lengths', () => {
      expect(() => encryptSecret('', TEST_HEX_KEY)).toThrow('Cannot encrypt empty secret');
      expect(() => encryptSecret('abc', '1234')).toThrow('32 bytes');
    });
  });

  describe('Shopify HMAC-SHA256 & Shop Domain Validation', () => {
    it('verifies valid Shopify Webhook HMAC and rejects tampered body', () => {
      const secret = 'shpss_test_secret';
      const body = JSON.stringify({ id: 12345, domain: 'test-store.myshopify.com' });
      const hmac = crypto.createHmac('sha256', secret).update(body, 'utf8').digest('base64');

      expect(verifyShopifyWebhookHmac(body, hmac, secret)).toBe(true);
      expect(verifyShopifyWebhookHmac(body + ' ', hmac, secret)).toBe(false);
      expect(verifyShopifyWebhookHmac(body, 'invalid_hmac', secret)).toBe(false);
    });

    it('verifies Shopify OAuth query HMAC in sorted parameter order', () => {
      const secret = 'shpss_oauth_secret';
      const queryParams = {
        code: 'auth_code_123',
        shop: 'kashcash-demo.myshopify.com',
        state: 'oauth_nonce_xyz',
        timestamp: '1700000000',
      };
      const message =
        'code=auth_code_123&shop=kashcash-demo.myshopify.com&state=oauth_nonce_xyz&timestamp=1700000000';
      const hmac = crypto.createHmac('sha256', secret).update(message, 'utf8').digest('hex');

      expect(verifyShopifyOAuthHmac({ ...queryParams, hmac }, secret)).toBe(true);
      expect(
        verifyShopifyOAuthHmac({ ...queryParams, shop: 'evil.myshopify.com', hmac }, secret)
      ).toBe(false);
    });

    it('strictly validates *.myshopify.com domains to prevent SSRF', () => {
      expect(isValidShopDomain('kashcash-store.myshopify.com')).toBe(true);
      expect(isValidShopDomain('store123.myshopify.com')).toBe(true);
      expect(isValidShopDomain('evil.com')).toBe(false);
      expect(isValidShopDomain('myshopify.com.evil.com')).toBe(false);
      expect(isValidShopDomain('https://store.myshopify.com')).toBe(false);
      expect(isValidShopDomain('../store.myshopify.com')).toBe(false);
      expect(isValidShopDomain('')).toBe(false);
    });

    it('performs constant-time string equality checks accurately', () => {
      expect(timingSafeStringEqual('kc_order_123', 'kc_order_123')).toBe(true);
      expect(timingSafeStringEqual('kc_order_123', 'kc_order_124')).toBe(false);
      expect(timingSafeStringEqual('short', 'longer_string')).toBe(false);
    });
  });
});
