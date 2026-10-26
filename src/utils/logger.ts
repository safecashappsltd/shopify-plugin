import pino from 'pino';
import { config } from '../config/env.js';

export const logger = pino({
  level: config.NODE_ENV === 'test' ? 'silent' : config.NODE_ENV === 'production' ? 'info' : 'debug',
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers["x-api-key"]',
      'req.headers["x-shopify-access-token"]',
      'merchant_token',
      'MerchantToken',
      'merchantToken',
      'accessToken',
    ],
    censor: '[REDACTED]',
  },
  base: {
    service: 'shopify-kashcash-payments',
    env: config.APP_ENV,
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});
