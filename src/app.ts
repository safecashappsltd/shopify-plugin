import crypto from 'node:crypto';
import express, { Express, NextFunction, Request, Response } from 'express';
import helmet from 'helmet';
import { AppConfig } from './config/env.js';
import { KashCashRepository } from './db/database.js';
import { createAuthAndMerchantRouter } from './routes/authAndMerchantRoutes.js';
import {
  createKashCashBackChannelRouter,
  RequestWithRawBody,
} from './routes/kashcashBackChannelRoutes.js';
import { createShopifySessionRouter } from './routes/shopifySessionRoutes.js';
import { createRateLimiter } from './security/rateLimiter.js';
import { KashCashClient } from './services/kashcashClient.js';
import { ShopifyPaymentsClient } from './services/shopifyPaymentsClient.js';
import { logger } from './utils/logger.js';

export interface AppDependencies {
  appConfig: AppConfig;
  repo: KashCashRepository;
  kashcashClient: KashCashClient;
  shopifyClient: ShopifyPaymentsClient;
}

export function createApp(deps: AppDependencies): Express {
  const { appConfig, repo, kashcashClient, shopifyClient } = deps;
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  // Security HTTP headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          connectSrc: ["'self'"],
          frameAncestors: ["'self'", 'https://*.myshopify.com', 'https://admin.shopify.com'],
        },
      },
      referrerPolicy: {
        policy: 'no-referrer',
      },
      strictTransportSecurity: {
        maxAge: 31536000,
        includeSubDomains: true,
      },
    })
  );

  // Sliding-window IP rate limiter against brute-force & enumeration
  app.use(
    createRateLimiter({
      windowMs: 60_000,
      maxRequests: 180,
    })
  );

  // Request ID tracing
  app.use((req: Request, res: Response, next: NextFunction) => {
    const requestId =
      req.header('shopify-request-id') ??
      req.header('x-request-id') ??
      crypto.randomUUID();
    res.setHeader('X-Request-Id', requestId);
    next();
  });

  // Capture raw request body for RSA-SHA512 (KashCash) and HMAC-SHA256 (Shopify) signature verification
  app.use(
    express.json({
      limit: '256kb',
      verify: (req: RequestWithRawBody, _res, buf) => {
        req.rawBody = buf.toString('utf8');
      },
    })
  );

  // Minimal health check endpoint — zero internal URL or environment disclosure
  app.get('/healthz', (_req: Request, res: Response) => {
    const dbOk = repo.ping();
    const status = dbOk ? 200 : 503;
    res.status(status).json({
      status: dbOk ? 'ok' : 'degraded',
    });
  });

  // Mount route modules
  app.use(
    createKashCashBackChannelRouter({
      appConfig,
      repo,
      kashcashClient,
      shopifyClient,
    })
  );
  app.use(
    createShopifySessionRouter({
      appConfig,
      repo,
      kashcashClient,
      shopifyClient,
    })
  );
  app.use(
    createAuthAndMerchantRouter({
      appConfig,
      repo,
      shopifyClient,
    })
  );

  // 404 Not Found handler (does not reflect untrusted path input)
  app.use((_req: Request, res: Response) => {
    res.status(404).json({
      error: 'Resource not found',
      code: 'ROUTE_NOT_FOUND',
    });
  });

  // Centralized error handler
  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof SyntaxError && 'body' in err) {
      res.status(400).json({
        error: 'Malformed JSON body',
        code: 'INVALID_JSON',
      });
      return;
    }

    logger.error({ err, method: req.method, path: req.path }, 'Unhandled application error');
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_SERVER_ERROR',
    });
  });

  return app;
}
