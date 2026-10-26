import crypto from 'node:crypto';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config/env.js';
import { KashCashRepository } from '../src/db/database.js';
import { createMerchantAdminToken } from '../src/routes/authAndMerchantRoutes.js';
import { signKashCashPayload } from '../src/security/crypto.js';
import { KashCashClient } from '../src/services/kashcashClient.js';
import { ShopifyPaymentsClient } from '../src/services/shopifyPaymentsClient.js';

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const TEST_SHOP = 'kashcash-israel.myshopify.com';
const TEST_SECRET = 'shpss_integration_test_secret_key';
const TEST_ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

describe('KashCash Shopify Payments App - End-to-End Integration & Security Tests', () => {
  let repo: KashCashRepository;

  beforeEach(() => {
    repo = new KashCashRepository(':memory:', TEST_ENCRYPTION_KEY);
  });

  afterEach(() => {
    repo.close();
    vi.restoreAllMocks();
  });

  function buildTestEnvironment(overrides?: Record<string, string>) {
    const appConfig = loadConfig({
      NODE_ENV: 'test',
      APP_ENV: 'prod',
      APP_BASE_URL: 'https://shopify.safecashapps.com',
      SHOPIFY_API_KEY: 'shp_api_key_123',
      SHOPIFY_API_SECRET: TEST_SECRET,
      ENCRYPTION_KEY: TEST_ENCRYPTION_KEY,
      KASHCASH_PUBLIC_KEY_PEM: publicKey,
      ...overrides,
    });

    const kashcashFetch = vi.fn<typeof fetch>();
    const shopifyFetch = vi.fn<typeof fetch>();

    const kashcashClient = new KashCashClient(appConfig, kashcashFetch);
    const shopifyClient = new ShopifyPaymentsClient(appConfig, shopifyFetch);

    const app = createApp({
      appConfig,
      repo,
      kashcashClient,
      shopifyClient,
    });

    return { app, appConfig, kashcashFetch, shopifyFetch };
  }

  it('GET /healthz reports ok without leaking internal API URLs or environment names', async () => {
    const { app } = buildTestEnvironment({ APP_ENV: 'dev' });
    const res = await request(app).get('/healthz');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
    expect(res.body.environment).toBeUndefined();
    expect(res.body.kashcashApiUrl).toBeUndefined();
  });

  it('enforces non-default secrets when NODE_ENV is production', () => {
    expect(() =>
      loadConfig({
        NODE_ENV: 'production',
        ENCRYPTION_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      })
    ).toThrow(/Default ENCRYPTION_KEY is forbidden/);

    expect(() =>
      loadConfig({
        NODE_ENV: 'production',
        ENCRYPTION_KEY: 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
        SHOPIFY_API_KEY: 'dev_shopify_api_key',
      })
    ).toThrow(/Default SHOPIFY_API_KEY/);
  });

  it('completes OAuth installation, merchant onboarding settings, and paymentsAppsConfigure', async () => {
    const { app, shopifyFetch } = buildTestEnvironment();

    // 1. Start OAuth
    const authRes = await request(app).get(`/api/auth?shop=${TEST_SHOP}`);
    expect(authRes.status).toBe(302);
    const redirectLocation = new URL(authRes.headers.location!);
    expect(redirectLocation.hostname).toBe(TEST_SHOP);
    const state = redirectLocation.searchParams.get('state')!;
    expect(state).toBeTruthy();

    // 2. OAuth Callback
    shopifyFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ access_token: 'shpat_live_token_999' }), { status: 200 })
    );

    const callbackParams = {
      code: 'temp_oauth_code',
      shop: TEST_SHOP,
      state,
      timestamp: '1700000000',
    };
    const msg = Object.entries(callbackParams)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join('&');
    const hmac = crypto.createHmac('sha256', TEST_SECRET).update(msg).digest('hex');

    const cbRes = await request(app).get(
      `/api/auth/callback?${msg}&hmac=${hmac}`
    );
    expect(cbRes.status).toBe(302);
    expect(cbRes.headers.location).toContain(`/app?shop=${encodeURIComponent(TEST_SHOP)}`);

    // 3. Save merchant KashCash credentials (Business ID + Merchant Token)
    shopifyFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          data: {
            paymentsAppsConfigure: {
              paymentsAppConfiguration: { externalHandle: 'kashcash_515123456', ready: true },
              userErrors: [],
            },
          },
        }),
        { status: 200 }
      )
    );

    const sessionToken = createMerchantAdminToken(TEST_SHOP, TEST_SECRET);
    const saveRes = await request(app)
      .post('/api/merchant/settings')
      .send({
        shopDomain: TEST_SHOP,
        sessionToken,
        businessId: '515123456',
        merchantToken: 'kc_merchant_secret_token_abc',
        testMode: false,
      });

    expect(saveRes.status).toBe(200);
    expect(saveRes.body.ok).toBe(true);
    expect(saveRes.body.shopifyPaymentsSettingsUrl).toBe(
      `https://${TEST_SHOP}/services/payments_partners/gateways/shp_api_key_123/settings`
    );

    const savedMerchant = repo.getMerchant(TEST_SHOP);
    expect(savedMerchant?.isConfigured).toBe(true);
    expect(savedMerchant?.businessId).toBe('515123456');
    expect(savedMerchant?.merchantToken).toBe('kc_merchant_secret_token_abc');
  });

  it('processes full payment lifecycle with random 12-digit orderId, replay protection, and cumulative refund cap', async () => {
    const { app, kashcashFetch, shopifyFetch } = buildTestEnvironment({ APP_ENV: 'prod' });

    // Seed configured merchant
    repo.upsertMerchantOAuth(TEST_SHOP, 'shpat_merchant_token_1');
    repo.updateMerchantKashCashCredentials({
      shopDomain: TEST_SHOP,
      businessId: '515777888',
      merchantToken: 'kc_live_branch_api_key_999',
      testMode: false,
      isConfigured: true,
    });

    // Step 1: Shopify creates a payment session
    const paymentSessionPayload = {
      id: 'shopify_pay_session_001',
      gid: 'gid://shopify/PaymentSession/shopify_pay_session_001',
      amount: '249.90',
      currency: 'ILS',
      test: false,
      payment_method: {
        type: 'offsite',
        data: {
          cancel_url: `https://${TEST_SHOP}/checkouts/c/abc/processing?cancel=1`,
        },
      },
    };

    const sessionRes = await request(app)
      .post('/api/shopify/payment-session')
      .set('Shopify-Shop-Domain', TEST_SHOP)
      .send(paymentSessionPayload);

    expect(sessionRes.status).toBe(200);
    const redirectUrlObj = new URL(sessionRes.body.redirect_url);
    expect(redirectUrlObj.origin).toBe('https://prod-api.safecashapps.com');
    expect(redirectUrlObj.searchParams.get('baseUrl')).toBe('shopify.safecashapps.com/wp-json');

    const orderIdStr = redirectUrlObj.searchParams.get('orderId')!;
    expect(orderIdStr).toMatch(/^\d{12}$/);
    const orderId = Number(orderIdStr);

    // Step 2: KashCash server calls GET /wp-json/kashcash/v1/order/:orderId with RSA-SHA512 signature
    const orderPath = `/wp-json/kashcash/v1/order/${orderId}`;
    const getOrderSig = signKashCashPayload('GET', orderPath, '', privateKey);

    const orderRes = await request(app)
      .get(orderPath)
      .set('x-signature', getOrderSig);

    expect(orderRes.status).toBe(200);
    expect(orderRes.body).toMatchObject({
      id: orderId,
      total: 249.9,
      currency: 'ILS',
      business_id: '515777888',
      merchant_token: 'kc_live_branch_api_key_999',
    });
    expect(orderRes.body.order_key).toMatch(/^kc_order_/);
    const orderKey = orderRes.body.order_key as string;

    // Verify invalid signature on GET order is rejected with 400
    const badOrderRes = await request(app)
      .get(orderPath)
      .set('x-signature', 'invalid_signature');
    expect(badOrderRes.status).toBe(400);

    // Step 3: KashCash server invokes POST /wp-json/kashcash/v1/webhook/ on payment approval
    const kashcashTxId = '3422b448-2460-4fd2-9183-8000de6f8343';
    const webhookBodyObj = {
      orderId: String(orderId),
      status: 'approved',
      transactionId: kashcashTxId,
    };
    const webhookRawBody = JSON.stringify(webhookBodyObj);
    const webhookSig = signKashCashPayload(
      'POST',
      '/wp-json/kashcash/v1/webhook/',
      webhookRawBody,
      privateKey
    );

    // Mock KashCash transaction status verification returning { completed: true }
    kashcashFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ completed: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    // Mock Shopify paymentSessionResolve returning thank_you redirectUrl
    const shopifyThankYouUrl = `https://${TEST_SHOP}/checkouts/c/abc/thank_you`;
    shopifyFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          data: {
            paymentSessionResolve: {
              paymentSession: {
                id: paymentSessionPayload.gid,
                nextAction: {
                  action: 'REDIRECT',
                  context: { redirectUrl: shopifyThankYouUrl },
                },
              },
              userErrors: [],
            },
          },
        }),
        { status: 200 }
      )
    );

    const webhookRes = await request(app)
      .post('/wp-json/kashcash/v1/webhook/')
      .set('Content-Type', 'application/json')
      .set('x-signature', webhookSig)
      .send(webhookRawBody);

    expect(webhookRes.status).toBe(200);
    expect(webhookRes.text).toBe(shopifyThankYouUrl);

    // Security check: Attempting to reject an already APPROVED payment session must fail with 409
    const downgradeBody = JSON.stringify({
      orderId: String(orderId),
      status: 'rejected',
      transactionId: kashcashTxId,
    });
    const downgradeSig = signKashCashPayload(
      'POST',
      '/wp-json/kashcash/v1/webhook/',
      downgradeBody,
      privateKey
    );
    const downgradeRes = await request(app)
      .post('/wp-json/kashcash/v1/webhook/')
      .set('Content-Type', 'application/json')
      .set('x-signature', downgradeSig)
      .send(downgradeBody);
    expect(downgradeRes.status).toBe(409);
    expect(downgradeRes.body.code).toBe('INVALID_STATE_TRANSITION');

    // Security check: Replaying the same transactionId on a second order must fail with 409
    const secondSessionRes = await request(app)
      .post('/api/shopify/payment-session')
      .set('Shopify-Shop-Domain', TEST_SHOP)
      .send({
        ...paymentSessionPayload,
        id: 'shopify_pay_session_002',
        gid: 'gid://shopify/PaymentSession/shopify_pay_session_002',
      });
    const secondOrderId = new URL(secondSessionRes.body.redirect_url).searchParams.get('orderId')!;
    const replayBody = JSON.stringify({
      orderId: secondOrderId,
      status: 'approved',
      transactionId: kashcashTxId,
    });
    const replaySig = signKashCashPayload(
      'POST',
      '/wp-json/kashcash/v1/webhook/',
      replayBody,
      privateKey
    );
    const replayRes = await request(app)
      .post('/wp-json/kashcash/v1/webhook/')
      .set('Content-Type', 'application/json')
      .set('x-signature', replaySig)
      .send(replayBody);
    expect(replayRes.status).toBe(409);
    expect(replayRes.body.code).toBe('TRANSACTION_REPLAY_DETECTED');

    // Step 4: Customer browser is redirected by KashCash to /checkout/order-received/:orderId/?key=...
    const returnRes = await request(app).get(
      `/checkout/order-received/${orderId}/?key=${encodeURIComponent(orderKey)}`
    );
    expect(returnRes.status).toBe(302);
    expect(returnRes.headers.location).toBe(shopifyThankYouUrl);

    // Wrong key on /checkout/order-received/:orderId must return 403
    const badKeyRes = await request(app).get(
      `/checkout/order-received/${orderId}/?key=wrong_key`
    );
    expect(badKeyRes.status).toBe(403);

    // Security check: Another store cannot refund this store's payment (Cross-Tenant Isolation)
    const otherShop = 'attacker-store.myshopify.com';
    repo.upsertMerchantOAuth(otherShop, 'shpat_attacker');
    repo.updateMerchantKashCashCredentials({
      shopDomain: otherShop,
      businessId: '515999000',
      merchantToken: 'kc_attacker_token',
      testMode: false,
      isConfigured: true,
    });
    const crossTenantRefundRes = await request(app)
      .post('/api/shopify/refund-session')
      .set('Shopify-Shop-Domain', otherShop)
      .send({
        id: 'ref_attack',
        gid: 'gid://shopify/RefundSession/ref_attack',
        payment_id: 'shopify_pay_session_001',
        amount: '50.00',
        currency: 'ILS',
      });
    expect(crossTenantRefundRes.status).toBe(404);

    // Step 5: Merchant initiates a partial Refund (150.00 out of 249.90) in Shopify Admin
    kashcashFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ transactionId: 'kc-refund-tx-777' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );
    shopifyFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          data: {
            refundSessionResolve: {
              refundSession: { id: 'gid://shopify/RefundSession/ref_001' },
              userErrors: [],
            },
          },
        }),
        { status: 200 }
      )
    );

    const refundRes = await request(app)
      .post('/api/shopify/refund-session')
      .set('Shopify-Shop-Domain', TEST_SHOP)
      .send({
        id: 'ref_001',
        gid: 'gid://shopify/RefundSession/ref_001',
        payment_id: 'shopify_pay_session_001',
        amount: '150.00',
        currency: 'ILS',
      });

    expect(refundRes.status).toBe(201);
    expect(refundRes.body.status).toBe('RESOLVED');
    expect(refundRes.body.refundTransactionId).toBe('kc-refund-tx-777');

    // Security check: Second refund of 150.00 (total 300.00 > 249.90) must be rejected with 422 REFUND_AMOUNT_EXCEEDED
    const overRefundRes = await request(app)
      .post('/api/shopify/refund-session')
      .set('Shopify-Shop-Domain', TEST_SHOP)
      .send({
        id: 'ref_002',
        gid: 'gid://shopify/RefundSession/ref_002',
        payment_id: 'shopify_pay_session_001',
        amount: '150.00',
        currency: 'ILS',
      });
    expect(overRefundRes.status).toBe(422);
    expect(overRefundRes.body.code).toBe('REFUND_AMOUNT_EXCEEDED');
  });

  it('handles rejected payments, unsupported currencies, mTLS enforcement, and GDPR webhooks', async () => {
    const { app, shopifyFetch } = buildTestEnvironment({
      MTLS_REQUIRED: 'true',
      MTLS_VERIFY_HEADER: 'x-client-cert-verify',
    });

    repo.upsertMerchantOAuth(TEST_SHOP, 'shpat_merchant_token_2');
    repo.updateMerchantKashCashCredentials({
      shopDomain: TEST_SHOP,
      businessId: '515000111',
      merchantToken: 'kc_token_222',
      testMode: true,
      isConfigured: true,
    });

    // 1. Missing mTLS header is rejected with 401
    const noMtlsRes = await request(app)
      .post('/api/shopify/payment-session')
      .set('Shopify-Shop-Domain', TEST_SHOP)
      .send({});
    expect(noMtlsRes.status).toBe(401);

    // 2. Non-HTTPS cancel_url is rejected with 400
    const httpCancelRes = await request(app)
      .post('/api/shopify/payment-session')
      .set('Shopify-Shop-Domain', TEST_SHOP)
      .set('x-client-cert-verify', 'SUCCESS')
      .send({
        id: 'sess_http',
        gid: 'gid://shopify/PaymentSession/sess_http',
        amount: '50.00',
        currency: 'ILS',
        test: true,
        payment_method: {
          type: 'offsite',
          data: { cancel_url: `http://${TEST_SHOP}/cancel` },
        },
      });
    expect(httpCancelRes.status).toBe(400);

    // 3. Unsupported currency (USD) is rejected with 422
    const usdRes = await request(app)
      .post('/api/shopify/payment-session')
      .set('Shopify-Shop-Domain', TEST_SHOP)
      .set('x-client-cert-verify', 'SUCCESS')
      .send({
        id: 'sess_usd',
        gid: 'gid://shopify/PaymentSession/sess_usd',
        amount: '50.00',
        currency: 'USD',
        test: true,
        payment_method: {
          type: 'offsite',
          data: { cancel_url: `https://${TEST_SHOP}/cancel` },
        },
      });
    expect(usdRes.status).toBe(422);
    expect(usdRes.body.code).toBe('CURRENCY_NOT_SUPPORTED');

    // 4. Create valid test session -> routes to stage-api even in prod APP_ENV because merchant testMode=true
    const validRes = await request(app)
      .post('/api/shopify/payment-session')
      .set('Shopify-Shop-Domain', TEST_SHOP)
      .set('x-client-cert-verify', 'SUCCESS')
      .send({
        id: 'sess_reject_test',
        gid: 'gid://shopify/PaymentSession/sess_reject_test',
        amount: '80.00',
        currency: 'ILS',
        test: false,
        payment_method: {
          type: 'offsite',
          data: { cancel_url: `https://${TEST_SHOP}/cancel` },
        },
      });
    expect(validRes.status).toBe(200);
    expect(validRes.body.redirect_url).toContain('https://stage-api.safecashapps.com');
    const createdOrderId = new URL(validRes.body.redirect_url).searchParams.get('orderId')!;

    // 5. Reject webhook from KashCash
    shopifyFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          data: {
            paymentSessionReject: {
              paymentSession: {
                id: 'gid://shopify/PaymentSession/sess_reject_test',
                nextAction: {
                  action: 'REDIRECT',
                  context: { redirectUrl: `https://${TEST_SHOP}/checkouts/c/abc/payment_error` },
                },
              },
              userErrors: [],
            },
          },
        }),
        { status: 200 }
      )
    );

    const rejectBody = JSON.stringify({
      orderId: createdOrderId,
      status: 'rejected',
      transactionId: 'tx-rejected-001',
    });
    const rejectSig = signKashCashPayload(
      'POST',
      '/wp-json/kashcash/v1/webhook/',
      rejectBody,
      privateKey
    );

    const rejectWebhookRes = await request(app)
      .post('/wp-json/kashcash/v1/webhook/')
      .set('Content-Type', 'application/json')
      .set('x-signature', rejectSig)
      .send(rejectBody);

    expect(rejectWebhookRes.status).toBe(200);
    expect(rejectWebhookRes.text).toBe('Order status: failed');

    // 6. GDPR shop/redact webhook deletes merchant data
    const gdprBody = JSON.stringify({ shop_id: 123, shop_domain: TEST_SHOP });
    const gdprHmac = crypto
      .createHmac('sha256', TEST_SECRET)
      .update(gdprBody, 'utf8')
      .digest('base64');

    const gdprRes = await request(app)
      .post('/api/shopify/webhooks/compliance')
      .set('Content-Type', 'application/json')
      .set('X-Shopify-Topic', 'shop/redact')
      .set('X-Shopify-Shop-Domain', TEST_SHOP)
      .set('X-Shopify-Hmac-Sha256', gdprHmac)
      .send(gdprBody);

    expect(gdprRes.status).toBe(200);
    expect(repo.getMerchant(TEST_SHOP)).toBeNull();
  });
});
