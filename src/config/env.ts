import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

/**
 * Default RSA Public Key used by KashCash ECommerceBackChannel (RequestSigningHandler)
 * to sign requests to /wp-json/kashcash/v1/order/{orderId} and /wp-json/kashcash/v1/webhook/
 */
export const DEFAULT_KASHCASH_PUBLIC_KEY_PEM = [
  '-----BEGIN PUBLIC KEY-----',
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5KYc1nzOeNfyWOEyhRKR',
  'VY7mJqaC5tr5N3bHNBG3fl/nMqkKIWeuxXKXZ97eeb48H8lfcsnEDbR4z0s0rj/s',
  'dr76GuI599xA5uXfcYysUHC61oGhX2bE+jwE/mq9jbCgq0vB+KqAt/6pHBjvh2Ax',
  'u1X6jbZ7Y9JjjRkht2JsI+DFHiT5/tb9JtH2GE+9bNa0QkfxoSe4F5Ie18BGddIt',
  '0XYX/vH2rbjevfBzuGiZF+GiGmzQE1BEJ0kbGSstnS+Y6OJDAMNgE3ocEJXkhQoQ',
  'irISr3M43SDxwIWOhvdPl7X4R7Eu7jZN0BSa5IC1AEAxg5WHQPZNMUtNSo21t1dJ',
  'DQIDAQAB',
  '-----END PUBLIC KEY-----',
].join('\n');

const DEFAULT_DEV_ENCRYPTION_KEY =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'staging', 'production']).default('development'),
  APP_ENV: z.enum(['dev', 'prod']).default('dev'),
  PORT: z.coerce.number().int().positive().default(3000),
  APP_BASE_URL: z.string().url().default('https://shopify-dev.safecashapps.com'),
  SHOPIFY_API_KEY: z.string().min(1).default('dev_shopify_api_key'),
  SHOPIFY_API_SECRET: z.string().min(1).default('dev_shopify_api_secret'),
  SHOPIFY_SCOPES: z.string().default('write_payment_gateways,write_payment_sessions'),
  SHOPIFY_API_VERSION: z.string().default('2025-01'),
  ENCRYPTION_KEY: z
    .string()
    .regex(/^[0-9a-fA-F]{64}$/, 'ENCRYPTION_KEY must be a 64-character hex string (32 bytes)')
    .default(DEFAULT_DEV_ENCRYPTION_KEY),
  DATABASE_PATH: z.string().min(1).default('./data/kashcash-shopify.db'),
  KASHCASH_STAGE_API_URL: z.string().url().default('https://stage-api.safecashapps.com'),
  KASHCASH_PROD_API_URL: z.string().url().default('https://prod-api.safecashapps.com'),
  KASHCASH_PUBLIC_KEY_PEM: z
    .string()
    .optional()
    .transform((val) =>
      val && val.trim().length > 0 ? val.replace(/\\n/g, '\n') : DEFAULT_KASHCASH_PUBLIC_KEY_PEM
    ),
  KASHCASH_HTTP_TIMEOUT_MS: z.coerce.number().int().positive().default(10000),
  SHOPIFY_HTTP_TIMEOUT_MS: z.coerce.number().int().positive().default(10000),
  MTLS_VERIFY_HEADER: z.string().optional().default(''),
  MTLS_REQUIRED: z
    .string()
    .optional()
    .default('false')
    .transform((val) => val === 'true' || val === '1'),
});

export type AppConfig = z.infer<typeof envSchema>;

export function loadConfig(overrides?: Partial<Record<string, string>>): AppConfig {
  const raw = { ...process.env, ...overrides };
  const parsed = envSchema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid environment configuration: ${issues}`);
  }

  const data = parsed.data;
  if (data.NODE_ENV === 'production') {
    if (data.ENCRYPTION_KEY === DEFAULT_DEV_ENCRYPTION_KEY) {
      throw new Error(
        'Security Error: Default ENCRYPTION_KEY is forbidden when NODE_ENV=production'
      );
    }
    if (
      data.SHOPIFY_API_KEY === 'dev_shopify_api_key' ||
      data.SHOPIFY_API_SECRET === 'dev_shopify_api_secret'
    ) {
      throw new Error(
        'Security Error: Default SHOPIFY_API_KEY / SHOPIFY_API_SECRET are forbidden when NODE_ENV=production'
      );
    }
  }

  return data;
}

export const config: AppConfig = loadConfig();
