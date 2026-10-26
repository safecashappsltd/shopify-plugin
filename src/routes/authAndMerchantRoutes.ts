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
    .min(6, 'Merchant Token is required (minimum 6 characters)')
    .max(512, 'Merchant Token is too long'),
  testMode: z.boolean().default(false),
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

export function createAuthAndMerchantRouter(deps: {
  appConfig: AppConfig;
  repo: KashCashRepository;
  shopifyClient: ShopifyPaymentsClient;
}): Router {
  const { appConfig, repo, shopifyClient } = deps;
  const router = Router();

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
   * Renders the Merchant Onboarding & Settings page (similar to WooCommerce KashCash settings).
   */
  router.get('/app', (req: Request, res: Response) => {
    const query = req.query as Record<string, string | string[] | undefined>;
    const shop = typeof query.shop === 'string' ? query.shop.trim().toLowerCase() : '';

    if (!isValidShopDomain(shop)) {
      res.status(400).type('text/html; charset=utf-8').send(`<!DOCTYPE html>
<html lang="he" dir="rtl">
<head><meta charset="UTF-8"><title>KashCash for Shopify</title></head>
<body style="font-family:sans-serif;padding:40px;text-align:center;">
  <h1>KashCash Payments for Shopify</h1>
  <p>נא לגשת לעמוד זה מתוך ממשק הניהול של חנות ה-Shopify שלך.</p>
</body>
</html>`);
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
    const isConfigured = merchant.isConfigured;
    const isTestMode = merchant.testMode || appConfig.APP_ENV === 'dev';

    res.status(200).type('text/html; charset=utf-8').send(`<!DOCTYPE html>
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
      padding: 24px 16px;
      line-height: 1.5;
    }
    .wrapper {
      max-width: 640px;
      margin: 0 auto;
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 24px;
    }
    .header h1 {
      font-size: 1.5rem;
      font-weight: 700;
    }
    .card {
      background: var(--surface);
      border-radius: 12px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 0 0 1px rgba(63,63,68,0.05);
      padding: 28px 24px;
      margin-bottom: 20px;
    }
    .status-banner {
      padding: 12px 16px;
      border-radius: 8px;
      margin-bottom: 20px;
      font-size: 0.92rem;
      font-weight: 500;
      display: flex;
      align-items: center;
      gap: 8px;
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
    .form-group {
      margin-bottom: 20px;
    }
    label {
      display: block;
      font-weight: 600;
      margin-bottom: 6px;
      font-size: 0.95rem;
    }
    .help-text {
      font-size: 0.84rem;
      color: var(--muted);
      margin-top: 4px;
    }
    input[type="text"],
    input[type="password"] {
      width: 100%;
      padding: 11px 14px;
      border: 1px solid var(--border);
      border-radius: 8px;
      font-size: 1rem;
      min-height: 44px;
      transition: border-color 0.15s;
      direction: ltr;
      text-align: left;
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
    .btn-submit {
      width: 100%;
      min-height: 48px;
      background: var(--primary);
      color: #ffffff;
      border: none;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 600;
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
    @media (max-width: 480px) {
      .card { padding: 20px 16px; }
      .header h1 { font-size: 1.25rem; }
    }
  </style>
</head>
<body>
  <main class="wrapper">
    <header class="header">
      <h1>KashCash Payments - הגדרות חיבור</h1>
    </header>

    <section class="card" aria-labelledby="settings-heading">
      <div class="status-banner ${isConfigured ? 'configured' : 'pending'}" role="status">
        <span>${
          isConfigured
            ? '✅ החנות מחוברת ומוגדרת לסליקה מול KashCash (' + escapeHtml(shop) + ')'
            : '⚠️ נא להזין את פרטי הסוחר מ-KashCash כדי להפעיל את אמצעי התשלום בחנות (' + escapeHtml(shop) + ')'
        }</span>
      </div>

      <form id="settingsForm" novalidate>
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
          <p class="help-text">מזהה העסק כפי שמופיע במערכת KashCash.</p>
          <p class="field-error" id="businessIdError" role="alert">נא להזין Business ID תקין (לפחות 2 תווים).</p>
        </div>

        <div class="form-group">
          <label for="merchantToken">Merchant Token (טוקן סוחר)</label>
          <input
            type="password"
            id="merchantToken"
            name="merchantToken"
            placeholder="${isConfigured ? '•••••••••••••••• (הזן טוקן חדש לעדכון)' : 'הדבק כאן את ה-Merchant Token'}"
            required
            autocomplete="off"
            aria-describedby="merchantTokenError"
          />
          <p class="help-text">הטוקן נשמר מוצפן ומשמש לאימות העסקאות מול KashCash.</p>
          <p class="field-error" id="merchantTokenError" role="alert">נא להזין Merchant Token תקין (לפחות 6 תווים).</p>
        </div>

        <div class="form-group">
          <label class="checkbox-row" for="testMode">
            <input type="checkbox" id="testMode" name="testMode" ${isTestMode ? 'checked' : ''} />
            <span>מצב בדיקות (Test Mode)</span>
          </label>
          <p class="help-text">כאשר מסומן, ניתן לבצע עסקאות בדיקה לפני העלייה לאוויר.</p>
        </div>

        <button type="submit" class="btn-submit" id="submitBtn">שמור והפעל ב-Shopify</button>
        <div id="toast" class="toast" role="alert" aria-live="polite"></div>
      </form>
    </section>
  </main>

  <script>
    (function() {
      var form = document.getElementById('settingsForm');
      var businessIdInput = document.getElementById('businessId');
      var merchantTokenInput = document.getElementById('merchantToken');
      var testModeInput = document.getElementById('testMode');
      var businessIdError = document.getElementById('businessIdError');
      var merchantTokenError = document.getElementById('merchantTokenError');
      var submitBtn = document.getElementById('submitBtn');
      var toast = document.getElementById('toast');

      function validateBusinessId() {
        var val = businessIdInput.value.trim();
        var valid = val.length >= 2;
        businessIdInput.classList.toggle('input-error', !valid);
        businessIdError.style.display = valid ? 'none' : 'block';
        return valid;
      }

      function validateMerchantToken() {
        var val = merchantTokenInput.value.trim();
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
          submitBtn.textContent = 'שמור והפעל ב-Shopify';

          if (!result.ok) {
            toast.className = 'toast error';
            toast.textContent = result.body.error || 'אירעה שגיאה בשמירת ההגדרות';
            return;
          }

          toast.className = 'toast success';
          toast.textContent = 'ההגדרות נשמרו בהצלחה! מעביר להגדרות התשלום ב-Shopify...';
          if (result.body.shopifyPaymentsSettingsUrl) {
            setTimeout(function() {
              window.location.href = result.body.shopifyPaymentsSettingsUrl;
            }, 1200);
          }
        })
        .catch(function() {
          submitBtn.disabled = false;
          submitBtn.textContent = 'שמור והפעל ב-Shopify';
          toast.className = 'toast error';
          toast.textContent = 'שגיאת תקשורת מול השרת. נא לנסות שוב.';
        });
      });
    })();
  </script>
</body>
</html>`);
  });

  /**
   * POST /api/merchant/settings
   * Saves the merchant's Business ID & Merchant Token (encrypted) and calls Shopify `paymentsAppsConfigure(ready: true)`.
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
        merchantToken,
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
      // Note: We do not store any customer PII (names, emails, phones) in our database.
      logger.info({ topic, shopDomain }, 'Processed GDPR compliance webhook');
    }

    res.status(200).json({ received: true });
  });

  return router;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
