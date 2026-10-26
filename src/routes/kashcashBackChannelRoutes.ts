import { Request, Response, Router } from 'express';
import { z } from 'zod';
import { AppConfig } from '../config/env.js';
import { KashCashRepository } from '../db/database.js';
import { timingSafeStringEqual, verifyKashCashSignature } from '../security/crypto.js';
import { KashCashClient } from '../services/kashcashClient.js';
import { ShopifyPaymentsClient } from '../services/shopifyPaymentsClient.js';
import { logger } from '../utils/logger.js';

const webhookBodySchema = z.object({
  orderId: z.union([z.string(), z.number()]).transform((v) => String(v).trim()),
  status: z.string().min(1),
  transactionId: z.string().min(1),
  token: z.string().optional(),
});

export interface RequestWithRawBody extends Request {
  rawBody?: string;
}

export function createKashCashBackChannelRouter(deps: {
  appConfig: AppConfig;
  repo: KashCashRepository;
  kashcashClient: KashCashClient;
  shopifyClient: ShopifyPaymentsClient;
}): Router {
  const { appConfig, repo, kashcashClient, shopifyClient } = deps;
  const router = Router();

  /**
   * Back-channel endpoint invoked by KashCash server (`IECommerceBackChannel.GetOrderDetails`):
   * GET /wp-json/kashcash/v1/order/:orderId
   */
  router.get('/wp-json/kashcash/v1/order/:orderId', (req: RequestWithRawBody, res: Response) => {
    const rawOrderId = typeof req.params.orderId === 'string' ? req.params.orderId : '';
    if (!/^\d+$/.test(rawOrderId)) {
      res.status(400).json({
        error: 'Invalid orderId parameter',
        code: 'INVALID_ORDER_ID',
      });
      return;
    }

    const signatureHeader = req.header('x-signature');
    const canonicalPath = `/wp-json/kashcash/v1/order/${rawOrderId}`;
    const isVerified =
      verifyKashCashSignature({
        method: 'GET',
        pathAndQuery: canonicalPath,
        rawBody: req.rawBody ?? '',
        signatureBase64: signatureHeader,
        publicKeyPem: appConfig.KASHCASH_PUBLIC_KEY_PEM,
      }) ||
      verifyKashCashSignature({
        method: 'GET',
        pathAndQuery: req.originalUrl,
        rawBody: req.rawBody ?? '',
        signatureBase64: signatureHeader,
        publicKeyPem: appConfig.KASHCASH_PUBLIC_KEY_PEM,
      });

    if (!isVerified) {
      logger.warn({ orderId: rawOrderId, path: req.originalUrl }, 'Invalid RSA signature on GET order');
      res.status(400).json({
        message: 'Invalid Signature',
        error: 'Invalid Signature',
        code: 'INVALID_SIGNATURE',
      });
      return;
    }

    const orderId = Number(rawOrderId);
    const session = repo.getPaymentSessionByOrderId(orderId);
    if (!session) {
      res.status(404).json({
        message: 'Order does not exist',
        error: 'Order does not exist',
        code: 'ORDER_NOT_FOUND',
      });
      return;
    }

    const merchant = repo.getMerchant(session.shopDomain);
    if (!merchant || !merchant.businessId || !merchant.merchantToken) {
      logger.error({ shopDomain: session.shopDomain, orderId }, 'Merchant credentials missing for order');
      res.status(400).json({
        message: 'Merchant is not configured',
        error: 'Merchant is not configured',
        code: 'MERCHANT_NOT_CONFIGURED',
      });
      return;
    }

    res.status(200).json({
      id: session.orderId,
      total: Number(session.amount),
      currency: session.currency,
      business_id: merchant.businessId,
      merchant_token: merchant.merchantToken,
      order_key: session.orderKey,
    });
  });

  /**
   * Back-channel webhook invoked by KashCash (`IECommerceBackChannel.OrderStatusChanged`):
   * POST /wp-json/kashcash/v1/webhook/
   */
  const handleWebhook = async (req: RequestWithRawBody, res: Response): Promise<void> => {
    const signatureHeader = req.header('x-signature');
    const rawBody = req.rawBody ?? JSON.stringify(req.body ?? {});

    const isVerified =
      verifyKashCashSignature({
        method: 'POST',
        pathAndQuery: '/wp-json/kashcash/v1/webhook/',
        rawBody,
        signatureBase64: signatureHeader,
        publicKeyPem: appConfig.KASHCASH_PUBLIC_KEY_PEM,
      }) ||
      verifyKashCashSignature({
        method: 'POST',
        pathAndQuery: '/wp-json/kashcash/v1/webhook',
        rawBody,
        signatureBase64: signatureHeader,
        publicKeyPem: appConfig.KASHCASH_PUBLIC_KEY_PEM,
      });

    if (!isVerified) {
      logger.warn({ path: req.originalUrl }, 'Invalid RSA signature on KashCash webhook');
      res.status(400).json({
        message: 'Authentication failed',
        error: 'Authentication failed',
        code: 'INVALID_SIGNATURE',
      });
      return;
    }

    const parsed = webhookBodySchema.safeParse(req.body);
    if (!parsed.success || !/^\d+$/.test(parsed.data.orderId)) {
      res.status(400).json({
        message: 'Invalid webhook payload',
        error: 'Invalid webhook payload',
        code: 'INVALID_PAYLOAD',
      });
      return;
    }

    const { status, transactionId } = parsed.data;
    const orderId = Number(parsed.data.orderId);

    const session = repo.getPaymentSessionByOrderId(orderId);
    if (!session) {
      res.status(400).json({
        message: 'Order does not exist',
        error: 'Order does not exist',
        code: 'ORDER_NOT_FOUND',
      });
      return;
    }

    const merchant = repo.getMerchant(session.shopDomain);
    if (!merchant || !merchant.merchantToken) {
      res.status(400).json({
        message: 'Merchant not found or unconfigured',
        error: 'Merchant not found or unconfigured',
        code: 'MERCHANT_NOT_CONFIGURED',
      });
      return;
    }

    const normalizedStatus = status.toLowerCase();

    if (normalizedStatus === 'approved') {
      // Idempotency: if already approved and resolved, return the existing redirect URL
      if (session.status === 'APPROVED' && session.redirectUrl) {
        res.status(200).type('text/plain').send(session.redirectUrl);
        return;
      }

      const isCompleted = await kashcashClient.verifyTransactionCompleted({
        transactionId,
        merchantToken: merchant.merchantToken,
        testMode: session.testMode,
      });

      if (!isCompleted) {
        logger.warn(
          { orderId, transactionId, shopDomain: session.shopDomain },
          'Webhook reported approved, but KashCash transaction status check returned completed=false'
        );
        res.status(400).json({
          message: 'Error: No Transaction',
          error: 'Transaction is not marked as completed in KashCash',
          code: 'TRANSACTION_NOT_COMPLETED',
        });
        return;
      }

      try {
        const resolved = await shopifyClient.resolvePaymentSession({
          shopDomain: session.shopDomain,
          accessToken: merchant.accessToken,
          shopifyGid: session.shopifyGid,
        });

        repo.updatePaymentSessionStatus({
          orderId,
          status: 'APPROVED',
          kashcashTransactionId: transactionId,
          redirectUrl: resolved.redirectUrl,
        });

        logger.info(
          { orderId, transactionId, shopDomain: session.shopDomain },
          'Payment session resolved in Shopify'
        );

        res.status(200).type('text/plain').send(resolved.redirectUrl);
        return;
      } catch (err) {
        logger.error({ err, orderId, transactionId }, 'Failed to resolve payment session in Shopify');
        res.status(502).json({
          error: 'Failed to resolve payment session with Shopify',
          code: 'SHOPIFY_RESOLVE_ERROR',
        });
        return;
      }
    }

    if (normalizedStatus === 'rejected') {
      if (session.status === 'REJECTED') {
        res.status(200).type('text/plain').send('Order status: failed');
        return;
      }

      try {
        const rejected = await shopifyClient.rejectPaymentSession({
          shopDomain: session.shopDomain,
          accessToken: merchant.accessToken,
          shopifyGid: session.shopifyGid,
          merchantMessage: 'Payment was rejected by the customer in KashCash.',
        });

        repo.updatePaymentSessionStatus({
          orderId,
          status: 'REJECTED',
          kashcashTransactionId: transactionId,
          redirectUrl: rejected.redirectUrl || session.cancelUrl,
        });

        logger.info(
          { orderId, transactionId, shopDomain: session.shopDomain },
          'Payment session rejected in Shopify'
        );

        res.status(200).type('text/plain').send('Order status: failed');
        return;
      } catch (err) {
        logger.error({ err, orderId, transactionId }, 'Failed to reject payment session in Shopify');
        res.status(502).json({
          error: 'Failed to reject payment session with Shopify',
          code: 'SHOPIFY_REJECT_ERROR',
        });
        return;
      }
    }

    res.status(400).json({
      error: `Unsupported status: ${status}`,
      code: 'UNSUPPORTED_STATUS',
    });
  };

  router.post('/wp-json/kashcash/v1/webhook', handleWebhook);
  router.post('/wp-json/kashcash/v1/webhook/', handleWebhook);

  /**
   * Front-channel return endpoint invoked when KashCash's payment page or mobile app
   * redirects the customer after payment completion:
   * GET /checkout/order-received/:orderId?key=:orderKey
   */
  router.get('/checkout/order-received/:orderId', async (req: Request, res: Response) => {
    const rawOrderId = typeof req.params.orderId === 'string' ? req.params.orderId : '';
    const providedKey = typeof req.query.key === 'string' ? req.query.key : '';

    if (!/^\d+$/.test(rawOrderId)) {
      res.status(400).send('Invalid order reference');
      return;
    }

    const orderId = Number(rawOrderId);
    const session = repo.getPaymentSessionByOrderId(orderId);
    if (!session) {
      res.status(404).send('Order session not found');
      return;
    }

    if (!providedKey || !timingSafeStringEqual(providedKey, session.orderKey)) {
      res.status(403).send('Invalid order key');
      return;
    }

    if (session.status === 'APPROVED' && session.redirectUrl) {
      res.redirect(302, session.redirectUrl);
      return;
    }

    if (session.status === 'REJECTED' || session.status === 'CANCELED') {
      res.redirect(302, session.redirectUrl ?? session.cancelUrl);
      return;
    }

    // Handle race condition: browser arrived before async webhook finished processing
    const candidateTxId =
      session.kashcashTransactionId ??
      (typeof req.query.transactionId === 'string' ? req.query.transactionId : null);

    if (candidateTxId) {
      const merchant = repo.getMerchant(session.shopDomain);
      if (merchant?.merchantToken) {
        const completed = await kashcashClient.verifyTransactionCompleted({
          transactionId: candidateTxId,
          merchantToken: merchant.merchantToken,
          testMode: session.testMode,
        });

        if (completed) {
          try {
            const resolved = await shopifyClient.resolvePaymentSession({
              shopDomain: session.shopDomain,
              accessToken: merchant.accessToken,
              shopifyGid: session.shopifyGid,
            });
            repo.updatePaymentSessionStatus({
              orderId,
              status: 'APPROVED',
              kashcashTransactionId: candidateTxId,
              redirectUrl: resolved.redirectUrl,
            });
            res.redirect(302, resolved.redirectUrl);
            return;
          } catch (err) {
            logger.error({ err, orderId }, 'Failed to resolve session during front-channel return');
          }
        }
      }
    }

    // Render auto-polling completion screen while waiting for webhook
    const statusEndpoint = `/api/shopify/session-status/${orderId}?key=${encodeURIComponent(providedKey)}`;
    const fallbackCancelUrl = session.cancelUrl;

    res.status(200).type('text/html; charset=utf-8').send(`<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>KashCash - משלים תשלום...</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f4f6f8;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      color: #202223;
    }
    .card {
      background: #fff;
      border-radius: 16px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08);
      max-width: 420px;
      width: 100%;
      padding: 36px 28px;
      text-align: center;
    }
    .spinner {
      width: 48px;
      height: 48px;
      border: 4px solid #e1e3e5;
      border-top-color: #008c8c;
      border-radius: 50%;
      animation: spin 0.9s linear infinite;
      margin: 0 auto 20px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    h1 { font-size: 1.25rem; margin-bottom: 10px; }
    p { color: #6d7175; font-size: 0.95rem; line-height: 1.5; }
    .btn {
      display: inline-block;
      margin-top: 20px;
      padding: 12px 24px;
      background: #008c8c;
      color: #fff;
      text-decoration: none;
      border-radius: 8px;
      font-weight: 600;
      min-height: 44px;
    }
  </style>
</head>
<body>
  <div class="card" role="status" aria-live="polite">
    <div class="spinner" aria-hidden="true"></div>
    <h1 id="title">מאמת את התשלום מול KashCash...</h1>
    <p id="desc">אנא המתן מספר שניות, מיד תועבר חזרה לחנות.</p>
    <a id="cancelBtn" class="btn" href="${escapeHtml(fallbackCancelUrl)}" style="display:none;">חזרה לחנות</a>
  </div>
  <script>
    (function() {
      var attempts = 0;
      var maxAttempts = 20;
      function poll() {
        attempts++;
        fetch(${JSON.stringify(statusEndpoint)})
          .then(function(r) { return r.json(); })
          .then(function(data) {
            if (data.redirectUrl) {
              window.location.replace(data.redirectUrl);
              return;
            }
            if (attempts < maxAttempts) {
              setTimeout(poll, 1000);
            } else {
              document.getElementById('title').textContent = 'האימות מתעכב';
              document.getElementById('desc').textContent = 'ניתן לחזור לחנות או לרענן את העמוד.';
              document.getElementById('cancelBtn').style.display = 'inline-block';
            }
          })
          .catch(function() {
            if (attempts < maxAttempts) setTimeout(poll, 1500);
          });
      }
      setTimeout(poll, 800);
    })();
  </script>
</body>
</html>`);
  });

  /**
   * JSON polling endpoint used by the waiting page if the customer browser arrived before the webhook.
   */
  router.get('/api/shopify/session-status/:orderId', (req: Request, res: Response) => {
    const rawOrderId = typeof req.params.orderId === 'string' ? req.params.orderId : '';
    const providedKey = typeof req.query.key === 'string' ? req.query.key : '';

    if (!/^\d+$/.test(rawOrderId)) {
      res.status(400).json({ error: 'Invalid orderId', code: 'INVALID_ORDER_ID' });
      return;
    }

    const session = repo.getPaymentSessionByOrderId(Number(rawOrderId));
    if (!session || !providedKey || !timingSafeStringEqual(providedKey, session.orderKey)) {
      res.status(403).json({ error: 'Forbidden', code: 'FORBIDDEN' });
      return;
    }

    res.status(200).json({
      status: session.status,
      redirectUrl:
        session.status === 'APPROVED'
          ? session.redirectUrl
          : session.status === 'REJECTED' || session.status === 'CANCELED'
            ? session.redirectUrl ?? session.cancelUrl
            : null,
    });
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
