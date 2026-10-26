import { describe, expect, it, vi } from 'vitest';
import { loadConfig } from '../src/config/env.js';
import { KashCashClient } from '../src/services/kashcashClient.js';
import { ShopifyPaymentsClient } from '../src/services/shopifyPaymentsClient.js';

describe('KashCashClient & ShopifyPaymentsClient Unit Tests', () => {
  describe('KashCashClient Environment (DEV/STAGE vs PROD) & API Calls', () => {
    it('uses stage-api in DEV environment regardless of session test flag', () => {
      const devConfig = loadConfig({
        NODE_ENV: 'test',
        APP_ENV: 'dev',
        APP_BASE_URL: 'https://shopify-dev.safecashapps.com',
      });
      const client = new KashCashClient(devConfig);

      expect(client.getApiBaseUrl(false)).toBe('https://stage-api.safecashapps.com');
      expect(client.getApiBaseUrl(true)).toBe('https://stage-api.safecashapps.com');

      const redirectUrl = client.buildPaymentPageUrl(100005, false);
      expect(redirectUrl).toBe(
        'https://stage-api.safecashapps.com/api/external/v1/ecommerce/payment/page/?orderId=100005&baseUrl=shopify-dev.safecashapps.com%2Fwp-json'
      );
    });

    it('uses prod-api in PROD environment when testMode=false, and stage-api when testMode=true', () => {
      const prodConfig = loadConfig({
        NODE_ENV: 'test',
        APP_ENV: 'prod',
        APP_BASE_URL: 'https://shopify.safecashapps.com',
      });
      const client = new KashCashClient(prodConfig);

      expect(client.getApiBaseUrl(false)).toBe('https://prod-api.safecashapps.com');
      expect(client.getApiBaseUrl(true)).toBe('https://stage-api.safecashapps.com');

      const prodRedirectUrl = client.buildPaymentPageUrl(100042, false);
      expect(prodRedirectUrl).toBe(
        'https://prod-api.safecashapps.com/api/external/v1/ecommerce/payment/page/?orderId=100042&baseUrl=shopify.safecashapps.com%2Fwp-json'
      );
    });

    it('retries on HTTP 503 and verifies transaction status completion', async () => {
      const cfg = loadConfig({ NODE_ENV: 'test', APP_ENV: 'prod' });
      const mockFetch = vi
        .fn<typeof fetch>()
        .mockResolvedValueOnce(new Response('Service Unavailable', { status: 503 }))
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ completed: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          })
        );

      const client = new KashCashClient(cfg, mockFetch);
      const completed = await client.verifyTransactionCompleted({
        transactionId: 'tx-123',
        merchantToken: 'merch-token-xyz',
        testMode: false,
      });

      expect(completed).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('sends x-api-key and X-Business-Id headers when initiating a refund', async () => {
      const cfg = loadConfig({ NODE_ENV: 'test', APP_ENV: 'prod' });
      const mockFetch = vi.fn<typeof fetch>().mockResolvedValueOnce(
        new Response(JSON.stringify({ transactionId: 'refund-guid-999' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const client = new KashCashClient(cfg, mockFetch);
      const result = await client.refundTransaction({
        transactionId: 'orig-guid-111',
        businessId: '515999888',
        merchantToken: 'secret-api-key',
        amount: 75.5,
        externalRefundId: 'shopify-refund-1',
        testMode: false,
      });

      expect(result.success).toBe(true);
      expect(result.refundTransactionId).toBe('refund-guid-999');

      const [calledUrl, calledInit] = mockFetch.mock.calls[0]!;
      expect(calledUrl).toBe('https://prod-api.safecashapps.com/api/external/v1.0/transactions/refund');
      expect((calledInit?.headers as Record<string, string>)['x-api-key']).toBe('secret-api-key');
      expect((calledInit?.headers as Record<string, string>)['X-Business-Id']).toBe('515999888');
    });
  });

  describe('ShopifyPaymentsClient GraphQL Operations', () => {
    it('resolves payment session and extracts redirectUrl', async () => {
      const cfg = loadConfig({ NODE_ENV: 'test' });
      const mockFetch = vi.fn<typeof fetch>().mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: {
              paymentSessionResolve: {
                paymentSession: {
                  id: 'gid://shopify/PaymentSession/1',
                  nextAction: {
                    action: 'REDIRECT',
                    context: {
                      redirectUrl: 'https://test-shop.myshopify.com/checkouts/c/123/thank_you',
                    },
                  },
                },
                userErrors: [],
              },
            },
          }),
          { status: 200 }
        )
      );

      const shopifyClient = new ShopifyPaymentsClient(cfg, mockFetch);
      const res = await shopifyClient.resolvePaymentSession({
        shopDomain: 'test-shop.myshopify.com',
        accessToken: 'shpat_token',
        shopifyGid: 'gid://shopify/PaymentSession/1',
      });

      expect(res.redirectUrl).toBe('https://test-shop.myshopify.com/checkouts/c/123/thank_you');
    });

    it('throws when Shopify returns userErrors on paymentSessionResolve', async () => {
      const cfg = loadConfig({ NODE_ENV: 'test' });
      const mockFetch = vi.fn<typeof fetch>().mockResolvedValue(
        new Response(
          JSON.stringify({
            data: {
              paymentSessionResolve: {
                paymentSession: null,
                userErrors: [{ field: ['id'], message: 'Payment session already resolved' }],
              },
            },
          }),
          { status: 200 }
        )
      );

      const shopifyClient = new ShopifyPaymentsClient(cfg, mockFetch);
      await expect(
        shopifyClient.resolvePaymentSession({
          shopDomain: 'test-shop.myshopify.com',
          accessToken: 'shpat_token',
          shopifyGid: 'gid://shopify/PaymentSession/1',
        })
      ).rejects.toThrow('Payment session already resolved');
    });
  });
});
