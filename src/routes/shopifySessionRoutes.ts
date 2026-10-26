import { NextFunction, Request, Response, Router } from 'express';
import { z } from 'zod';
import { AppConfig } from '../config/env.js';
import { KashCashRepository } from '../db/database.js';
import { generateSecureToken, isValidShopDomain } from '../security/crypto.js';
import { KashCashClient } from '../services/kashcashClient.js';
import { ShopifyPaymentsClient } from '../services/shopifyPaymentsClient.js';
import { logger } from '../utils/logger.js';

const paymentSessionRequestSchema = z.object({
  id: z.string().min(1),
  gid: z.string().min(1),
  group: z.string().optional(),
  amount: z.union([z.string(), z.number()]).transform((v) => Number(v)),
  currency: z.string().min(3).max(3).transform((v) => v.toUpperCase()),
  test: z.boolean().default(false),
  merchant_locale: z.string().optional(),
  payment_method: z
    .object({
      type: z.string(),
      data: z
        .object({
          cancel_url: z.string().url(),
        })
        .passthrough(),
    })
    .passthrough(),
  proposed_at: z.string().optional(),
  kind: z.string().optional(),
});

const refundSessionRequestSchema = z.object({
  id: z.string().min(1),
  gid: z.string().min(1),
  payment_id: z.string().min(1),
  amount: z.union([z.string(), z.number()]).transform((v) => Number(v)),
  currency: z.string().min(3).max(3).transform((v) => v.toUpperCase()),
  test: z.boolean().optional().default(false),
  merchant_locale: z.string().optional(),
  proposed_at: z.string().optional(),
});

const captureOrVoidSessionSchema = z.object({
  id: z.string().min(1),
  gid: z.string().min(1),
  payment_id: z.string().min(1),
  amount: z
    .union([z.string(), z.number()])
    .optional()
    .transform((v) => (v !== undefined ? Number(v) : undefined)),
  currency: z.string().optional(),
  test: z.boolean().optional().default(false),
});

export function createShopifySessionRouter(deps: {
  appConfig: AppConfig;
  repo: KashCashRepository;
  kashcashClient: KashCashClient;
  shopifyClient: ShopifyPaymentsClient;
}): Router {
  const { appConfig, repo, kashcashClient, shopifyClient } = deps;
  const router = Router();

  /**
   * Optional mTLS verification middleware for Shopify Payments Apps endpoints.
   * In production behind NGINX / Envoy / AWS ALB / Cloudflare mTLS, verifies client certificate header.
   */
  const verifyMtlsIfRequired = (req: Request, res: Response, next: NextFunction): void => {
    if (!appConfig.MTLS_REQUIRED || !appConfig.MTLS_VERIFY_HEADER) {
      next();
      return;
    }

    const headerVal = req.header(appConfig.MTLS_VERIFY_HEADER);
    if (!headerVal || !['SUCCESS', '1', 'true', 'VALID'].includes(headerVal.trim())) {
      logger.warn({ path: req.path, headerVal }, 'Rejected request failing mTLS verification');
      res.status(401).json({
        error: 'Client certificate verification failed',
        code: 'MTLS_VERIFICATION_FAILED',
      });
      return;
    }

    next();
  };

  /**
   * POST /api/shopify/payment-session
   * Invoked by Shopify Checkout when a buyer selects KashCash as their payment method.
   * Returns `{ redirect_url: "https://{stage|prod}-api.safecashapps.com/api/external/v1/ecommerce/payment/page/?..." }`
   */
  router.post(
    '/api/shopify/payment-session',
    verifyMtlsIfRequired,
    (req: Request, res: Response) => {
      const shopDomain = req.header('shopify-shop-domain')?.trim().toLowerCase();
      if (!isValidShopDomain(shopDomain)) {
        res.status(400).json({
          error: 'Missing or invalid Shopify-Shop-Domain header',
          code: 'INVALID_SHOP_DOMAIN',
        });
        return;
      }

      const parsed = paymentSessionRequestSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid payment session payload',
          code: 'VALIDATION_ERROR',
          details: parsed.error.flatten(),
        });
        return;
      }

      const payload = parsed.data;

      if (payload.currency !== 'ILS') {
        res.status(422).json({
          error: `Unsupported currency: ${payload.currency}. Only ILS is supported.`,
          code: 'CURRENCY_NOT_SUPPORTED',
        });
        return;
      }

      if (!Number.isFinite(payload.amount) || payload.amount <= 0) {
        res.status(422).json({
          error: 'Payment amount must be greater than zero',
          code: 'INVALID_AMOUNT',
        });
        return;
      }

      const merchant = repo.getMerchant(shopDomain);
      if (!merchant || !merchant.isConfigured || !merchant.businessId || !merchant.merchantToken) {
        logger.error({ shopDomain }, 'Merchant is not configured for KashCash payments');
        res.status(422).json({
          error: 'Merchant has not configured KashCash credentials',
          code: 'MERCHANT_NOT_CONFIGURED',
        });
        return;
      }

      const effectiveTestMode =
        appConfig.APP_ENV === 'dev' || payload.test || merchant.testMode;

      const session = repo.createOrGetPaymentSession({
        shopifySessionId: payload.id,
        shopifyGid: payload.gid,
        shopDomain,
        amount: payload.amount,
        currency: payload.currency,
        testMode: effectiveTestMode,
        orderKey: generateSecureToken('kc_order', 20),
        cancelUrl: payload.payment_method.data.cancel_url,
      });

      const redirectUrl = kashcashClient.buildPaymentPageUrl(
        session.orderId,
        session.testMode
      );

      logger.info(
        {
          shopDomain,
          shopifySessionId: session.shopifySessionId,
          orderId: session.orderId,
          amount: session.amount,
          testMode: session.testMode,
        },
        'Created Shopify payment session and generated KashCash redirect_url'
      );

      res.status(200).json({
        redirect_url: redirectUrl,
      });
    }
  );

  /**
   * POST /api/shopify/refund-session
   * Invoked by Shopify when a merchant initiates a refund on an order paid via KashCash.
   */
  router.post(
    '/api/shopify/refund-session',
    verifyMtlsIfRequired,
    async (req: Request, res: Response) => {
      const shopDomain = req.header('shopify-shop-domain')?.trim().toLowerCase();
      if (!isValidShopDomain(shopDomain)) {
        res.status(400).json({
          error: 'Missing or invalid Shopify-Shop-Domain header',
          code: 'INVALID_SHOP_DOMAIN',
        });
        return;
      }

      const parsed = refundSessionRequestSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid refund session payload',
          code: 'VALIDATION_ERROR',
          details: parsed.error.flatten(),
        });
        return;
      }

      const payload = parsed.data;
      if (!Number.isFinite(payload.amount) || payload.amount <= 0) {
        res.status(422).json({
          error: 'Refund amount must be greater than zero',
          code: 'INVALID_AMOUNT',
        });
        return;
      }

      const merchant = repo.getMerchant(shopDomain);
      if (!merchant || !merchant.businessId || !merchant.merchantToken) {
        res.status(422).json({
          error: 'Merchant credentials not found',
          code: 'MERCHANT_NOT_CONFIGURED',
        });
        return;
      }

      const paymentSession = repo.getPaymentSessionByShopifyId(payload.payment_id);
      if (!paymentSession || !paymentSession.kashcashTransactionId) {
        res.status(404).json({
          error: 'Original KashCash payment transaction not found',
          code: 'ORIGINAL_PAYMENT_NOT_FOUND',
        });
        return;
      }

      const refundSession = repo.createOrGetRefundSession({
        shopifyRefundId: payload.id,
        shopifyGid: payload.gid,
        paymentSessionId: payload.payment_id,
        shopDomain,
        amount: payload.amount,
        currency: payload.currency,
      });

      // Idempotency: if already resolved, return 201 immediately
      if (refundSession.status === 'RESOLVED') {
        res.status(201).json({ status: 'RESOLVED' });
        return;
      }

      const refundResult = await kashcashClient.refundTransaction({
        transactionId: paymentSession.kashcashTransactionId,
        businessId: merchant.businessId,
        merchantToken: merchant.merchantToken,
        amount: payload.amount,
        externalRefundId: payload.id,
        testMode: paymentSession.testMode,
      });

      try {
        if (refundResult.success) {
          await shopifyClient.resolveRefundSession({
            shopDomain,
            accessToken: merchant.accessToken,
            shopifyGid: payload.gid,
          });

          repo.updateRefundSessionStatus({
            shopifyRefundId: payload.id,
            status: 'RESOLVED',
            kashcashRefundTransactionId: refundResult.refundTransactionId ?? null,
          });

          res.status(201).json({
            status: 'RESOLVED',
            refundTransactionId: refundResult.refundTransactionId,
          });
          return;
        } else {
          const message = refundResult.errorMessage ?? 'KashCash refund rejected';
          await shopifyClient.rejectRefundSession({
            shopDomain,
            accessToken: merchant.accessToken,
            shopifyGid: payload.gid,
            merchantMessage: message,
          });

          repo.updateRefundSessionStatus({
            shopifyRefundId: payload.id,
            status: 'REJECTED',
            errorMessage: message,
          });

          res.status(200).json({
            status: 'REJECTED',
            error: message,
            code: refundResult.errorCode ?? 'REFUND_REJECTED',
          });
          return;
        }
      } catch (err) {
        logger.error({ err, shopifyRefundId: payload.id }, 'Failed to update refund session in Shopify');
        res.status(502).json({
          error: 'Failed to synchronize refund session with Shopify',
          code: 'SHOPIFY_SYNC_ERROR',
        });
      }
    }
  );

  /**
   * POST /api/shopify/capture-session
   * KashCash ecommerce payments are immediate sale transactions, so capture resolves immediately.
   */
  router.post(
    '/api/shopify/capture-session',
    verifyMtlsIfRequired,
    async (req: Request, res: Response) => {
      const shopDomain = req.header('shopify-shop-domain')?.trim().toLowerCase();
      if (!isValidShopDomain(shopDomain)) {
        res.status(400).json({ error: 'Invalid shop domain', code: 'INVALID_SHOP_DOMAIN' });
        return;
      }

      const parsed = captureOrVoidSessionSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: 'Invalid capture payload', code: 'VALIDATION_ERROR' });
        return;
      }

      const merchant = repo.getMerchant(shopDomain);
      if (!merchant) {
        res.status(404).json({ error: 'Merchant not found', code: 'MERCHANT_NOT_FOUND' });
        return;
      }

      try {
        await shopifyClient.resolveCaptureSession({
          shopDomain,
          accessToken: merchant.accessToken,
          shopifyGid: parsed.data.gid,
        });
        res.status(200).json({ status: 'RESOLVED' });
      } catch (err) {
        logger.error({ err, shopDomain }, 'Failed to resolve capture session');
        res.status(502).json({ error: 'Failed to resolve capture session', code: 'SHOPIFY_ERROR' });
      }
    }
  );

  /**
   * POST /api/shopify/void-session
   * Cancels a pending KashCash request if not yet paid and resolves the void session in Shopify.
   */
  router.post(
    '/api/shopify/void-session',
    verifyMtlsIfRequired,
    async (req: Request, res: Response) => {
      const shopDomain = req.header('shopify-shop-domain')?.trim().toLowerCase();
      if (!isValidShopDomain(shopDomain)) {
        res.status(400).json({ error: 'Invalid shop domain', code: 'INVALID_SHOP_DOMAIN' });
        return;
      }

      const parsed = captureOrVoidSessionSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: 'Invalid void payload', code: 'VALIDATION_ERROR' });
        return;
      }

      const merchant = repo.getMerchant(shopDomain);
      if (!merchant || !merchant.businessId || !merchant.merchantToken) {
        res.status(404).json({ error: 'Merchant not configured', code: 'MERCHANT_NOT_CONFIGURED' });
        return;
      }

      const paymentSession = repo.getPaymentSessionByShopifyId(parsed.data.payment_id);
      if (paymentSession?.kashcashTransactionId) {
        await kashcashClient.cancelTransaction({
          transactionId: paymentSession.kashcashTransactionId,
          businessId: merchant.businessId,
          merchantToken: merchant.merchantToken,
          testMode: paymentSession.testMode,
        });
        repo.updatePaymentSessionStatus({
          orderId: paymentSession.orderId,
          status: 'CANCELED',
        });
      }

      try {
        await shopifyClient.resolveVoidSession({
          shopDomain,
          accessToken: merchant.accessToken,
          shopifyGid: parsed.data.gid,
        });
        res.status(200).json({ status: 'RESOLVED' });
      } catch (err) {
        logger.error({ err, shopDomain }, 'Failed to resolve void session');
        res.status(502).json({ error: 'Failed to resolve void session', code: 'SHOPIFY_ERROR' });
      }
    }
  );

  return router;
}
