import crypto from 'node:crypto';
import { Request, Response, Router } from 'express';
import { z } from 'zod';
import { AppConfig } from '../config/env.js';
import { KashCashRepository } from '../db/database.js';
import { RequestWithRawBody } from '../routes/kashcashBackChannelRoutes.js';
import {
  generateSecureToken,
  isValidShopDomain,
  timingSafeStringEqual,
  verifyShopifyOAuthHmac,
  verifyShopifyWebhookHmac,
} from '../security/crypto.js';
import { ShopifyPaymentsClient } from '../services/shopifyPaymentsClient.js';
import { logger } from '../utils/logger.js';

const merchantSettingsSchema = z.object({
  shopDomain: z.string().refine((val) => isValidShopDomain(val), {
    message: 'Invalid Shopify shop domain',
  }),
  sessionToken: z.string().min(10),
  businessId: z
    .string()
    .trim()
    .min(2, 'Business ID is required (minimum 2 characters)')
    .max(64, 'Business ID is too long'),
  merchantToken: z
    .string()
    .trim()
    .max(512, 'Merchant Token is too long')
    .optional()
    .default(''),
  testMode: z.boolean().default(false),
});

const merchantDisconnectSchema = z.object({
  shopDomain: z.string().refine((val) => isValidShopDomain(val), {
    message: 'Invalid Shopify shop domain',
  }),
  sessionToken: z.string().min(10),
});

/**
 * Generates an HMAC-signed session token bound to a specific shopDomain (1-hour expiry)
 * to authorize the merchant onboarding settings form submission.
 */
export function createMerchantAdminToken(
  shopDomain: string,
  secret: string,
  expiresAtMs = Date.now() + 3600 * 1000
): string {
  const payload = `${shopDomain}|${expiresAtMs}`;
  const sig = crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('hex');
  return Buffer.from(`${payload}|${sig}`, 'utf8').toString('base64url');
}

export function verifyMerchantAdminToken(
  token: string,
  expectedShopDomain: string,
  secret: string
): boolean {
  try {
    const decoded = Buffer.from(token, 'base64url').toString('utf8');
    const parts = decoded.split('|');
    if (parts.length !== 3) {
      return false;
    }
    const [shopDomain, expiresAtStr, providedSig] = parts;
    if (!shopDomain || !expiresAtStr || !providedSig) {
      return false;
    }
    if (shopDomain !== expectedShopDomain) {
      return false;
    }
    const expiresAt = Number(expiresAtStr);
    if (!Number.isFinite(expiresAt) || Date.now() > expiresAt) {
      return false;
    }

    const payload = `${shopDomain}|${expiresAtStr}`;
    const expectedSig = crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('hex');
    return timingSafeStringEqual(expectedSig, providedSig);
  } catch {
    return false;
  }
}

function maskSecretToken(token: string | null): string {
  if (!token || token.length < 4) {
    return '';
  }
  const suffix = token.slice(-4);
  return `••••••••••••${suffix}`;
}

export function createAuthAndMerchantRouter(deps: {
  appConfig: AppConfig;
  repo: KashCashRepository;
  shopifyClient: ShopifyPaymentsClient;
}): Router {
  const { appConfig, repo, shopifyClient } = deps;
  const router = Router();

  /**
   * GET /
   * Entry point when opening the app root URL.
   * Forwards to /app (preserving query string) so merchants never hit a 404.
   */
  router.get('/', (req: Request, res: Response) => {
    const queryIndex = req.originalUrl.indexOf('?');
    const querySuffix = queryIndex >= 0 ? req.originalUrl.slice(queryIndex) : '';
    res.redirect(302, `/app${querySuffix}`);
  });

  /**
   * GET /api/auth?shop=example.myshopify.com
   * Starts the Shopify OAuth 2.0 installation flow.
   */
  router.get('/api/auth', (req: Request, res: Response) => {
    const shop = typeof req.query.shop === 'string' ? req.query.shop.trim().toLowerCase() : '';
    if (!isValidShopDomain(shop)) {
      res.status(400).json({
        error: 'Invalid or missing shop parameter (must be *.myshopify.com)',
        code: 'INVALID_SHOP_DOMAIN',
      });
      return;
    }

    const state = generateSecureToken('oauth', 16);
    repo.saveOAuthState(state, shop, 600);

    const redirectUri = `${appConfig.APP_BASE_URL.replace(/\/+$/, '')}/api/auth/callback`;
    const authUrl = new URL(`https://${shop}/admin/oauth/authorize`);
    authUrl.searchParams.set('client_id', appConfig.SHOPIFY_API_KEY);
    authUrl.searchParams.set('scope', appConfig.SHOPIFY_SCOPES);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('state', state);

    res.redirect(302, authUrl.toString());
  });

  /**
   * GET /api/auth/callback
   * Validates Shopify OAuth HMAC & state, exchanges code for offline access token, and redirects to /app.
   */
  router.get('/api/auth/callback', async (req: Request, res: Response) => {
    const query = req.query as Record<string, string | string[] | undefined>;
    const shop = typeof query.shop === 'string' ? query.shop.trim().toLowerCase() : '';
    const code = typeof query.code === 'string' ? query.code.trim() : '';
    const state = typeof query.state === 'string' ? query.state.trim() : '';

    if (!isValidShopDomain(shop) || !code || !state) {
      res.status(400).json({
        error: 'Missing required OAuth callback parameters',
        code: 'INVALID_OAUTH_CALLBACK',
      });
      return;
    }

    if (!verifyShopifyOAuthHmac(query, appConfig.SHOPIFY_API_SECRET)) {
      logger.warn({ shop }, 'Invalid HMAC on Shopify OAuth callback');
      res.status(400).json({
        error: 'OAuth HMAC verification failed',
        code: 'INVALID_HMAC',
      });
      return;
    }

    if (!repo.consumeOAuthState(state, shop)) {
      logger.warn({ shop }, 'Invalid or expired OAuth state nonce');
      res.status(400).json({
        error: 'Invalid or expired OAuth state parameter',
        code: 'INVALID_STATE',
      });
      return;
    }

    try {
      const accessToken = await shopifyClient.exchangeOAuthCodeForToken({
        shopDomain: shop,
        code,
      });

      repo.upsertMerchantOAuth(shop, accessToken);

      const sessionToken = createMerchantAdminToken(shop, appConfig.SHOPIFY_API_SECRET);
      res.redirect(
        302,
        `/app?shop=${encodeURIComponent(shop)}&token=${encodeURIComponent(sessionToken)}`
      );
    } catch (err) {
      logger.error({ err, shop }, 'Failed to complete Shopify OAuth callback');
      res.status(502).json({
        error: 'Failed to exchange authorization code with Shopify',
        code: 'OAUTH_EXCHANGE_FAILED',
      });
    }
  });

  /**
   * GET /app
   * Renders the Guided 3-Step Merchant Onboarding & Maintenance Portal.
   */
  router.get('/app', (req: Request, res: Response) => {
    const query = req.query as Record<string, string | string[] | undefined>;
    const shop = typeof query.shop === 'string' ? query.shop.trim().toLowerCase() : '';

    // If opened directly without a ?shop= parameter, render the 1-Click Store Connect screen
    if (!isValidShopDomain(shop)) {
      res.status(200).type('text/html; charset=utf-8').send(renderQuickConnectHtml());
      return;
    }

    const merchant = repo.getMerchant(shop);
    if (!merchant) {
      res.redirect(302, `/api/auth?shop=${encodeURIComponent(shop)}`);
      return;
    }

    let sessionToken = typeof query.token === 'string' ? query.token : '';
    if (!sessionToken) {
      if (verifyShopifyOAuthHmac(query, appConfig.SHOPIFY_API_SECRET)) {
        sessionToken = createMerchantAdminToken(shop, appConfig.SHOPIFY_API_SECRET);
      }
    }

    if (!sessionToken || !verifyMerchantAdminToken(sessionToken, shop, appConfig.SHOPIFY_API_SECRET)) {
      res.redirect(302, `/api/auth?shop=${encodeURIComponent(shop)}`);
      return;
    }

    const currentBusinessId = merchant.businessId ?? '';
    const isConfigured = merchant.isConfigured && Boolean(merchant.merchantToken);
    const isTestMode = merchant.testMode || appConfig.APP_ENV === 'dev';
    const maskedToken = maskSecretToken(merchant.merchantToken);
    const shopifyPaymentsSettingsUrl = `https://${shop}/services/payments_partners/gateways/${appConfig.SHOPIFY_API_KEY}/settings`;

    res.status(200).type('text/html; charset=utf-8').send(
      renderOnboardingPortalHtml({
        shop,
        sessionToken,
        currentBusinessId,
        isConfigured,
        isTestMode,
        maskedToken,
        updatedAt: merchant.updatedAt,
        shopifyPaymentsSettingsUrl,
      })
    );
  });

  /**
   * POST /api/merchant/settings
   * Saves the merchant's Business ID & Merchant Token (encrypted) and calls Shopify `paymentsAppsConfigure(ready: true)`.
   * Supports keeping the existing Merchant Token on maintenance updates when merchantToken is left blank.
   */
  router.post('/api/merchant/settings', async (req: Request, res: Response) => {
    const parsed = merchantSettingsSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
      });
      return;
    }

    const { shopDomain, sessionToken, businessId, merchantToken, testMode } = parsed.data;

    if (!verifyMerchantAdminToken(sessionToken, shopDomain, appConfig.SHOPIFY_API_SECRET)) {
      res.status(401).json({
        error: 'Unauthorized or expired session token',
        code: 'UNAUTHORIZED',
      });
      return;
    }

    const merchant = repo.getMerchant(shopDomain);
    if (!merchant) {
      res.status(404).json({
        error: 'Merchant shop not installed',
        code: 'MERCHANT_NOT_FOUND',
      });
      return;
    }

    const effectiveMerchantToken =
      merchantToken.length > 0 ? merchantToken : (merchant.merchantToken ?? '');

    if (effectiveMerchantToken.length < 6) {
      res.status(400).json({
        error: 'נא להזין Merchant Token תקין (לפחות 6 תווים)',
        code: 'VALIDATION_ERROR',
      });
      return;
    }

    try {
      await shopifyClient.configurePaymentsApp({
        shopDomain,
        accessToken: merchant.accessToken,
        externalHandle: `kashcash_${businessId}`,
        ready: true,
      });

      repo.updateMerchantKashCashCredentials({
        shopDomain,
        businessId,
        merchantToken: effectiveMerchantToken,
        testMode,
        isConfigured: true,
      });

      const shopifyPaymentsSettingsUrl = `https://${shopDomain}/services/payments_partners/gateways/${appConfig.SHOPIFY_API_KEY}/settings`;

      logger.info({ shopDomain, businessId, testMode }, 'Merchant configured KashCash payments app');

      res.status(200).json({
        ok: true,
        shopifyPaymentsSettingsUrl,
      });
    } catch (err) {
      logger.error({ err, shopDomain }, 'Failed to configure Payments App in Shopify');
      res.status(502).json({
        error: 'Failed to activate payment gateway with Shopify API',
        code: 'SHOPIFY_CONFIGURE_ERROR',
      });
    }
  });

  /**
   * POST /api/merchant/disconnect
   * Allows a merchant to reset their KashCash credentials and mark the gateway as not ready in Shopify.
   */
  router.post('/api/merchant/disconnect', async (req: Request, res: Response) => {
    const parsed = merchantDisconnectSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: 'Invalid request payload',
        code: 'VALIDATION_ERROR',
      });
      return;
    }

    const { shopDomain, sessionToken } = parsed.data;
    if (!verifyMerchantAdminToken(sessionToken, shopDomain, appConfig.SHOPIFY_API_SECRET)) {
      res.status(401).json({
        error: 'Unauthorized or expired session token',
        code: 'UNAUTHORIZED',
      });
      return;
    }

    const merchant = repo.getMerchant(shopDomain);
    if (!merchant) {
      res.status(404).json({
        error: 'Merchant shop not installed',
        code: 'MERCHANT_NOT_FOUND',
      });
      return;
    }

    try {
      await shopifyClient.configurePaymentsApp({
        shopDomain,
        accessToken: merchant.accessToken,
        externalHandle: `kashcash_disconnected`,
        ready: false,
      });
    } catch (err) {
      logger.warn({ err, shopDomain }, 'Non-fatal error while unconfiguring Shopify Payments App');
    }

    repo.upsertMerchantOAuth(shopDomain, merchant.accessToken);
    repo.updateMerchantKashCashCredentials({
      shopDomain,
      businessId: '',
      merchantToken: 'disconnected',
      testMode: false,
      isConfigured: false,
    });

    res.status(200).json({ ok: true });
  });

  /**
   * POST /api/shopify/webhooks/app-uninstalled
   * Verifies Shopify HMAC-SHA256 over raw body and deletes merchant credentials on uninstall.
   */
  router.post(
    '/api/shopify/webhooks/app-uninstalled',
    (req: RequestWithRawBody, res: Response) => {
      const hmacHeader = req.header('x-shopify-hmac-sha256');
      const rawBody = req.rawBody ?? '';

      if (!verifyShopifyWebhookHmac(rawBody, hmacHeader, appConfig.SHOPIFY_API_SECRET)) {
        res.status(401).json({
          error: 'Invalid Shopify webhook HMAC',
          code: 'INVALID_HMAC',
        });
        return;
      }

      const shopDomain = req.header('x-shopify-shop-domain')?.trim().toLowerCase();
      if (shopDomain && isValidShopDomain(shopDomain)) {
        repo.deleteMerchant(shopDomain);
        logger.info({ shopDomain }, 'Deleted merchant records upon app/uninstalled webhook');
      }

      res.status(200).json({ received: true });
    }
  );

  /**
   * POST /api/shopify/webhooks/compliance
   * Mandatory Shopify GDPR / Privacy webhooks:
   * - customers/data_request
   * - customers/redact
   * - shop/redact
   */
  router.post('/api/shopify/webhooks/compliance', (req: RequestWithRawBody, res: Response) => {
    const hmacHeader = req.header('x-shopify-hmac-sha256');
    const rawBody = req.rawBody ?? '';

    if (!verifyShopifyWebhookHmac(rawBody, hmacHeader, appConfig.SHOPIFY_API_SECRET)) {
      res.status(401).json({
        error: 'Invalid Shopify webhook HMAC',
        code: 'INVALID_HMAC',
      });
      return;
    }

    const topic = req.header('x-shopify-topic')?.trim().toLowerCase();
    const shopDomain = req.header('x-shopify-shop-domain')?.trim().toLowerCase();

    if (topic === 'shop/redact' && shopDomain && isValidShopDomain(shopDomain)) {
      repo.deleteMerchant(shopDomain);
      logger.info({ shopDomain }, 'Redacted shop data on shop/redact GDPR webhook');
    } else {
      logger.info({ topic, shopDomain }, 'Processed GDPR compliance webhook');
    }

    res.status(200).json({ received: true });
  });

  return router;
}

function renderQuickConnectHtml(): string {
  return `<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>KashCash for Shopify - חיבור חנות מהיר</title>
  <style>
    :root {
      --primary: #008c8c;
      --primary-hover: #006b6b;
      --bg: #f6f6f7;
      --surface: #ffffff;
      --text: #202223;
      --muted: #6d7175;
      --border: #c9cccf;
      --error: #d72c0d;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px 16px;
      line-height: 1.5;
    }
    .card {
      background: var(--surface);
      border-radius: 16px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.07);
      max-width: 480px;
      width: 100%;
      padding: 36px 28px;
      text-align: center;
    }
    .logo-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 56px;
      height: 56px;
      border-radius: 14px;
      background: #e6f4f4;
      color: var(--primary);
      font-weight: 900;
      font-size: 1.4rem;
      margin-bottom: 16px;
    }
    h1 { font-size: 1.45rem; margin-bottom: 8px; }
    p { color: var(--muted); font-size: 0.95rem; margin-bottom: 24px; }
    .input-wrap { text-align: right; margin-bottom: 16px; }
    label { display: block; font-weight: 600; font-size: 0.9rem; margin-bottom: 6px; }
    input[type="text"] {
      width: 100%;
      padding: 12px 14px;
      border: 1px solid var(--border);
      border-radius: 10px;
      font-size: 1rem;
      min-height: 46px;
      direction: ltr;
      text-align: left;
    }
    input[type="text"]:focus {
      outline: 2px solid var(--primary);
      border-color: var(--primary);
    }
    .error-msg {
      color: var(--error);
      font-size: 0.85rem;
      margin-top: 6px;
      display: none;
    }
    button {
      width: 100%;
      min-height: 48px;
      background: var(--primary);
      color: #fff;
      border: none;
      border-radius: 10px;
      font-size: 1rem;
      font-weight: 700;
      cursor: pointer;
      transition: background 0.2s;
    }
    button:hover { background: var(--primary-hover); }
  </style>
</head>
<body>
  <main class="card">
    <div class="logo-badge" aria-hidden="true">KC</div>
    <h1>KashCash Payments for Shopify</h1>
    <p>הזן את כתובת חנות ה-Shopify שלך כדי להתחיל בהתקנה אוטומטית בתוך פחות מדקה:</p>
    <form id="connectForm" novalidate>
      <div class="input-wrap">
        <label for="shopInput">כתובת החנות (Shop Domain)</label>
        <input
          type="text"
          id="shopInput"
          placeholder="my-store.myshopify.com"
          required
          autocomplete="off"
        />
        <div id="shopError" class="error-msg" role="alert">נא להזין שם חנות תקין (לדוגמה: my-store.myshopify.com)</div>
      </div>
      <button type="submit">המשך להתקנה והגדרת החנות →</button>
    </form>
  </main>
  <script>
    (function() {
      var form = document.getElementById('connectForm');
      var input = document.getElementById('shopInput');
      var errorEl = document.getElementById('shopError');

      form.addEventListener('submit', function(e) {
        e.preventDefault();
        var raw = input.value.trim().toLowerCase().replace(/^https?:\\/\\//, '').replace(/\\/.*$/, '');
        if (raw && !raw.endsWith('.myshopify.com') && /^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(raw)) {
          raw = raw + '.myshopify.com';
        }
        if (!/^[a-z0-9][a-z0-9-]*\\.myshopify\\.com$/.test(raw)) {
          errorEl.style.display = 'block';
          return;
        }
        errorEl.style.display = 'none';
        window.location.href = '/api/auth?shop=' + encodeURIComponent(raw);
      });
    })();
  </script>
</body>
</html>`;
}

function renderOnboardingPortalHtml(params: {
  shop: string;
  sessionToken: string;
  currentBusinessId: string;
  isConfigured: boolean;
  isTestMode: boolean;
  maskedToken: string;
  updatedAt: string;
  shopifyPaymentsSettingsUrl: string;
}): string {
  const {
    shop,
    sessionToken,
    currentBusinessId,
    isConfigured,
    isTestMode,
    maskedToken,
    shopifyPaymentsSettingsUrl,
  } = params;

  return `<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>הגדרות סליקה KashCash - Shopify</title>
  <style>
    :root {
      --primary: #008c8c;
      --primary-hover: #006b6b;
      --bg: #f6f6f7;
      --surface: #ffffff;
      --text: #202223;
      --muted: #6d7175;
      --border: #c9cccf;
      --error: #d72c0d;
      --error-bg: #fff4f4;
      --success: #007f5f;
      --success-bg: #f1f8f5;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      padding: 28px 16px;
      line-height: 1.5;
    }
    .wrapper {
      max-width: 680px;
      margin: 0 auto;
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 20px;
    }
    .header h1 {
      font-size: 1.5rem;
      font-weight: 800;
    }
    .shop-pill {
      background: #e6f4f4;
      color: var(--primary);
      padding: 6px 14px;
      border-radius: 999px;
      font-size: 0.85rem;
      font-weight: 700;
      direction: ltr;
    }
    .steps-bar {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      margin-bottom: 22px;
    }
    .step-item {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px;
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 0.86rem;
      font-weight: 600;
    }
    .step-item.done {
      border-color: #95c9b4;
      background: var(--success-bg);
      color: var(--success);
    }
    .step-item.active {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(0, 140, 140, 0.15);
    }
    .step-num {
      width: 26px;
      height: 26px;
      border-radius: 50%;
      background: var(--primary);
      color: #fff;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 0.8rem;
      font-weight: 800;
      flex-shrink: 0;
    }
    .step-item.done .step-num {
      background: var(--success);
    }
    .card {
      background: var(--surface);
      border-radius: 14px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 0 0 1px rgba(63,63,68,0.05);
      padding: 28px 24px;
      margin-bottom: 20px;
    }
    .status-banner {
      padding: 14px 16px;
      border-radius: 10px;
      margin-bottom: 22px;
      font-size: 0.93rem;
      font-weight: 500;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
    }
    .status-banner.configured {
      background: var(--success-bg);
      color: var(--success);
      border: 1px solid #95c9b4;
    }
    .status-banner.pending {
      background: #fff5ea;
      color: #8a6116;
      border: 1px solid #e1b878;
    }
    .btn-shopify-link {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--success);
      color: #fff;
      text-decoration: none;
      padding: 8px 14px;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 700;
      min-height: 38px;
    }
    .form-group {
      margin-bottom: 20px;
    }
    label {
      display: block;
      font-weight: 700;
      margin-bottom: 6px;
      font-size: 0.95rem;
    }
    .help-text {
      font-size: 0.84rem;
      color: var(--muted);
      margin-top: 5px;
    }
    .token-input-wrapper {
      position: relative;
      display: flex;
      align-items: center;
    }
    input[type="text"],
    input[type="password"] {
      width: 100%;
      padding: 11px 14px;
      border: 1px solid var(--border);
      border-radius: 8px;
      font-size: 1rem;
      min-height: 46px;
      transition: border-color 0.15s;
      direction: ltr;
      text-align: left;
    }
    .toggle-secret-btn {
      position: absolute;
      right: 10px;
      background: #f1f2f3;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 4px 10px;
      font-size: 0.78rem;
      font-weight: 600;
      color: var(--text);
      cursor: pointer;
      min-height: 30px;
    }
    input[type="text"]:focus,
    input[type="password"]:focus {
      outline: 2px solid var(--primary);
      border-color: var(--primary);
    }
    input.input-error {
      border-color: var(--error);
      background: var(--error-bg);
    }
    .field-error {
      color: var(--error);
      font-size: 0.84rem;
      margin-top: 5px;
      display: none;
    }
    .checkbox-row {
      display: flex;
      align-items: center;
      gap: 10px;
      min-height: 44px;
      cursor: pointer;
    }
    .checkbox-row input[type="checkbox"] {
      width: 20px;
      height: 20px;
      accent-color: var(--primary);
    }
    .actions-row {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .btn-submit {
      width: 100%;
      min-height: 48px;
      background: var(--primary);
      color: #ffffff;
      border: none;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 700;
      cursor: pointer;
      transition: background 0.2s;
    }
    .btn-submit:hover:not(:disabled) {
      background: var(--primary-hover);
    }
    .btn-submit:disabled {
      opacity: 0.65;
      cursor: not-allowed;
    }
    .btn-secondary {
      width: 100%;
      min-height: 42px;
      background: transparent;
      color: var(--muted);
      border: 1px solid var(--border);
      border-radius: 8px;
      font-size: 0.88rem;
      font-weight: 600;
      cursor: pointer;
    }
    .btn-secondary:hover {
      color: var(--error);
      border-color: var(--error);
    }
    .toast {
      margin-top: 16px;
      padding: 14px 16px;
      border-radius: 8px;
      font-size: 0.92rem;
      display: none;
    }
    .toast.success {
      display: block;
      background: var(--success-bg);
      color: var(--success);
      border: 1px solid #95c9b4;
    }
    .toast.error {
      display: block;
      background: var(--error-bg);
      color: var(--error);
      border: 1px solid #f5c6cb;
    }
    .guide-list {
      padding-right: 20px;
      color: var(--muted);
      font-size: 0.9rem;
    }
    .guide-list li { margin-bottom: 6px; }
    @media (max-width: 560px) {
      .steps-bar { grid-template-columns: 1fr; }
      .card { padding: 20px 16px; }
      .header h1 { font-size: 1.25rem; }
    }
  </style>
</head>
<body>
  <main class="wrapper">
    <header class="header">
      <h1>KashCash Payments - הגדרות חיבור</h1>
      <span class="shop-pill">${escapeHtml(shop)}</span>
    </header>

    <nav class="steps-bar" aria-label="שלבי התקנה">
      <div class="step-item done">
        <span class="step-num">✓</span>
        <span>1. החנות מחוברת</span>
      </div>
      <div class="step-item ${isConfigured ? 'done' : 'active'}">
        <span class="step-num">${isConfigured ? '✓' : '2'}</span>
        <span>2. פרטי סוחר KashCash</span>
      </div>
      <div class="step-item ${isConfigured ? 'active' : ''}">
        <span class="step-num">3</span>
        <span>3. הפעלה ב-Shopify</span>
      </div>
    </nav>

    <section class="card" aria-labelledby="settings-heading">
      <div class="status-banner ${isConfigured ? 'configured' : 'pending'}" role="status">
        <span>${
          isConfigured
            ? '✅ החנות מוגדרת ומוכנה לסליקה מול KashCash'
            : '👋 שלב אחרון: הזן את ה-Business ID וה-Merchant Token שקיבלת מ-KashCash'
        }</span>
        ${
          isConfigured
            ? `<a class="btn-shopify-link" href="${escapeHtml(shopifyPaymentsSettingsUrl)}" target="_top">פתח הגדרות תשלום ב-Shopify ↗</a>`
            : ''
        }
      </div>

      <form id="settingsForm" novalidate data-is-configured="${isConfigured ? 'true' : 'false'}">
        <input type="hidden" id="shopDomain" value="${escapeHtml(shop)}" />
        <input type="hidden" id="sessionToken" value="${escapeHtml(sessionToken)}" />

        <div class="form-group">
          <label for="businessId">Business ID (מזהה עסק / ח.פ.)</label>
          <input
            type="text"
            id="businessId"
            name="businessId"
            value="${escapeHtml(currentBusinessId)}"
            placeholder="לדוגמה: 515000000"
            required
            aria-describedby="businessIdError"
          />
          <p class="help-text">מזהה העסק כפי שמופיע בפורטל העסקים של KashCash.</p>
          <p class="field-error" id="businessIdError" role="alert">נא להזין Business ID תקין (לפחות 2 תווים).</p>
        </div>

        <div class="form-group">
          <label for="merchantToken">Merchant Token (טוקן סוחר)</label>
          <div class="token-input-wrapper">
            <input
              type="password"
              id="merchantToken"
              name="merchantToken"
              placeholder="${
                isConfigured
                  ? `שמור במערכת (${escapeHtml(maskedToken)}) — השאר ריק או הזן טוקן חדש לעדכון`
                  : 'הדבק כאן את ה-Merchant Token'
              }"
              ${isConfigured ? '' : 'required'}
              autocomplete="off"
              aria-describedby="merchantTokenError"
            />
            <button type="button" class="toggle-secret-btn" id="toggleTokenBtn">הצג</button>
          </div>
          <p class="help-text">${
            isConfigured
              ? 'הטוקן שלך שמור ומוצפן במערכת. ניתן לעדכן הגדרות בלי להקליד אותו מחדש.'
              : 'הטוקן נשמר מוצפן ומשמש לאימות העסקאות וההחזרים מול KashCash.'
          }</p>
          <p class="field-error" id="merchantTokenError" role="alert">נא להזין Merchant Token תקין (לפחות 6 תווים).</p>
        </div>

        <div class="form-group">
          <label class="checkbox-row" for="testMode">
            <input type="checkbox" id="testMode" name="testMode" ${isTestMode ? 'checked' : ''} />
            <span>מצב בדיקות (Test Mode)</span>
          </label>
          <p class="help-text">סמן אפשרות זו לביצוע עסקאות בדיקה בלבד. לסליקת אמת בחנות השאר ללא סימון.</p>
        </div>

        <div class="actions-row">
          <button type="submit" class="btn-submit" id="submitBtn">
            ${isConfigured ? 'שמור שינויים והמשך ל-Shopify' : 'שמור והפעל את KashCash ב-Shopify'}
          </button>
          ${
            isConfigured
              ? '<button type="button" class="btn-secondary" id="disconnectBtn">איפוס / ניתוק פרטי סוחר</button>'
              : ''
          }
        </div>
        <div id="toast" class="toast" role="alert" aria-live="polite"></div>
      </form>
    </section>

    <section class="card">
      <h2 style="font-size:1.05rem;margin-bottom:10px;">איך זה עובד? (3 צעדים פשוטים)</h2>
      <ol class="guide-list">
        <li>מזינים למעלה את ה-<strong>Business ID</strong> ואת ה-<strong>Merchant Token</strong> מ-KashCash ולוחצים <strong>שמור והפעל</strong>.</li>
        <li>מועברים אוטומטית למסך <strong>Settings → Payments</strong> בחנות ה-Shopify ומפעילים (Activate) את <strong>KashCash</strong>.</li>
        <li>מרגע זה הלקוחות יכולים לשלם בקופה עם KashCash, וביצוע החזר כספי (Refund) מתוך הזמנה ב-Shopify מזכה את הלקוח ב-KashCash אוטומטית!</li>
      </ol>
    </section>
  </main>

  <script>
    (function() {
      var form = document.getElementById('settingsForm');
      var isConfigured = form.getAttribute('data-is-configured') === 'true';
      var businessIdInput = document.getElementById('businessId');
      var merchantTokenInput = document.getElementById('merchantToken');
      var toggleTokenBtn = document.getElementById('toggleTokenBtn');
      var testModeInput = document.getElementById('testMode');
      var businessIdError = document.getElementById('businessIdError');
      var merchantTokenError = document.getElementById('merchantTokenError');
      var submitBtn = document.getElementById('submitBtn');
      var disconnectBtn = document.getElementById('disconnectBtn');
      var toast = document.getElementById('toast');

      toggleTokenBtn.addEventListener('click', function() {
        var isPwd = merchantTokenInput.type === 'password';
        merchantTokenInput.type = isPwd ? 'text' : 'password';
        toggleTokenBtn.textContent = isPwd ? 'הסתר' : 'הצג';
      });

      function validateBusinessId() {
        var val = businessIdInput.value.trim();
        var valid = val.length >= 2;
        businessIdInput.classList.toggle('input-error', !valid);
        businessIdError.style.display = valid ? 'none' : 'block';
        return valid;
      }

      function validateMerchantToken() {
        var val = merchantTokenInput.value.trim();
        if (isConfigured && val.length === 0) {
          merchantTokenInput.classList.remove('input-error');
          merchantTokenError.style.display = 'none';
          return true;
        }
        var valid = val.length >= 6;
        merchantTokenInput.classList.toggle('input-error', !valid);
        merchantTokenError.style.display = valid ? 'none' : 'block';
        return valid;
      }

      businessIdInput.addEventListener('blur', validateBusinessId);
      merchantTokenInput.addEventListener('blur', validateMerchantToken);

      form.addEventListener('submit', function(e) {
        e.preventDefault();
        toast.className = 'toast';
        toast.textContent = '';

        var bValid = validateBusinessId();
        var mValid = validateMerchantToken();
        if (!bValid || !mValid) {
          return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = 'שומר ומגדיר מול Shopify...';

        fetch('/api/merchant/settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            shopDomain: document.getElementById('shopDomain').value,
            sessionToken: document.getElementById('sessionToken').value,
            businessId: businessIdInput.value.trim(),
            merchantToken: merchantTokenInput.value.trim(),
            testMode: testModeInput.checked
          })
        })
        .then(function(res) {
          return res.json().then(function(body) {
            return { ok: res.ok, body: body };
          });
        })
        .then(function(result) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'שמור שינויים והמשך ל-Shopify';

          if (!result.ok) {
            toast.className = 'toast error';
            toast.textContent = result.body.error || 'אירעה שגיאה בשמירת ההגדרות';
            return;
          }

          toast.className = 'toast success';
          toast.textContent = 'ההגדרות נשמרו בהצלחה! מעביר להגדרות התשלום ב-Shopify...';
          if (result.body.shopifyPaymentsSettingsUrl) {
            setTimeout(function() {
              window.top.location.href = result.body.shopifyPaymentsSettingsUrl;
            }, 1100);
          }
        })
        .catch(function() {
          submitBtn.disabled = false;
          submitBtn.textContent = 'שמור והפעל את KashCash ב-Shopify';
          toast.className = 'toast error';
          toast.textContent = 'שגיאת תקשורת מול השרת. נא לנסות שוב.';
        });
      });

      if (disconnectBtn) {
        disconnectBtn.addEventListener('click', function() {
          if (!window.confirm('האם לאפס את פרטי החיבור של KashCash לחנות זו?')) {
            return;
          }
          disconnectBtn.disabled = true;
          fetch('/api/merchant/disconnect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              shopDomain: document.getElementById('shopDomain').value,
              sessionToken: document.getElementById('sessionToken').value
            })
          }).then(function() {
            window.location.reload();
          });
        });
      }
    })();
  </script>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
