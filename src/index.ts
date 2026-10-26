import { config } from './config/env.js';
import { KashCashRepository } from './db/database.js';
import { KashCashClient } from './services/kashcashClient.js';
import { ShopifyPaymentsClient } from './services/shopifyPaymentsClient.js';
import { createApp } from './app.js';
import { logger } from './utils/logger.js';

const repo = new KashCashRepository(config.DATABASE_PATH, config.ENCRYPTION_KEY);
const kashcashClient = new KashCashClient(config);
const shopifyClient = new ShopifyPaymentsClient(config);

const app = createApp({
  appConfig: config,
  repo,
  kashcashClient,
  shopifyClient,
});

const server = app.listen(config.PORT, () => {
  logger.info(
    {
      port: config.PORT,
      appEnv: config.APP_ENV,
      appBaseUrl: config.APP_BASE_URL,
      kashcashApi: kashcashClient.getApiBaseUrl(config.APP_ENV === 'dev'),
    },
    'KashCash Shopify Payments App started'
  );
});

function shutdown(signal: string): void {
  logger.info({ signal }, 'Received shutdown signal, draining connections...');
  server.close((err) => {
    if (err) {
      logger.error({ err }, 'Error closing HTTP server');
      process.exit(1);
    }
    try {
      repo.close();
      logger.info('Database closed cleanly. Exiting.');
      process.exit(0);
    } catch (dbErr) {
      logger.error({ dbErr }, 'Error closing database');
      process.exit(1);
    }
  });

  setTimeout(() => {
    logger.warn('Forced exit after shutdown timeout');
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
