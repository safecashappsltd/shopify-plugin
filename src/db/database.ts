import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import { decryptSecret, encryptSecret } from '../security/crypto.js';

export type PaymentSessionStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'CANCELED';
export type RefundSessionStatus = 'PENDING' | 'RESOLVED' | 'REJECTED';

export interface MerchantRecord {
  shopDomain: string;
  accessToken: string;
  businessId: string | null;
  merchantToken: string | null;
  testMode: boolean;
  isConfigured: boolean;
  installedAt: string;
  updatedAt: string;
}

export interface PaymentSessionRecord {
  orderId: number;
  shopifySessionId: string;
  shopifyGid: string;
  shopDomain: string;
  amount: number;
  currency: string;
  testMode: boolean;
  orderKey: string;
  cancelUrl: string;
  redirectUrl: string | null;
  kashcashTransactionId: string | null;
  status: PaymentSessionStatus;
  createdAt: string;
  updatedAt: string;
}

export interface CreatePaymentSessionInput {
  shopifySessionId: string;
  shopifyGid: string;
  shopDomain: string;
  amount: number;
  currency: string;
  testMode: boolean;
  orderKey: string;
  cancelUrl: string;
}

export interface RefundSessionRecord {
  shopifyRefundId: string;
  shopifyGid: string;
  paymentSessionId: string;
  shopDomain: string;
  amount: number;
  currency: string;
  kashcashRefundTransactionId: string | null;
  status: RefundSessionStatus;
  errorMessage: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateRefundSessionInput {
  shopifyRefundId: string;
  shopifyGid: string;
  paymentSessionId: string;
  shopDomain: string;
  amount: number;
  currency: string;
}

interface RawMerchantRow {
  shop_domain: string;
  access_token_encrypted: string;
  business_id: string | null;
  merchant_token_encrypted: string | null;
  test_mode: number;
  is_configured: number;
  installed_at: string;
  updated_at: string;
}

interface RawPaymentSessionRow {
  order_id: number;
  shopify_session_id: string;
  shopify_gid: string;
  shop_domain: string;
  amount: number;
  currency: string;
  test_mode: number;
  order_key: string;
  cancel_url: string;
  redirect_url: string | null;
  kashcash_transaction_id: string | null;
  status: PaymentSessionStatus;
  created_at: string;
  updated_at: string;
}

interface RawRefundSessionRow {
  shopify_refund_id: string;
  shopify_gid: string;
  payment_session_id: string;
  shop_domain: string;
  amount: number;
  currency: string;
  kashcash_refund_transaction_id: string | null;
  status: RefundSessionStatus;
  error_message: string | null;
  created_at: string;
  updated_at: string;
}

export const MIGRATIONS_UP = `
CREATE TABLE IF NOT EXISTS merchants (
  shop_domain TEXT PRIMARY KEY,
  access_token_encrypted TEXT NOT NULL,
  business_id TEXT,
  merchant_token_encrypted TEXT,
  test_mode INTEGER NOT NULL DEFAULT 0,
  is_configured INTEGER NOT NULL DEFAULT 0,
  installed_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_states (
  state TEXT PRIMARY KEY,
  shop_domain TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states(expires_at);

CREATE TABLE IF NOT EXISTS payment_sessions (
  order_id INTEGER PRIMARY KEY,
  shopify_session_id TEXT NOT NULL UNIQUE,
  shopify_gid TEXT NOT NULL,
  shop_domain TEXT NOT NULL,
  amount REAL NOT NULL,
  currency TEXT NOT NULL,
  test_mode INTEGER NOT NULL DEFAULT 0,
  order_key TEXT NOT NULL,
  cancel_url TEXT NOT NULL,
  redirect_url TEXT,
  kashcash_transaction_id TEXT UNIQUE,
  status TEXT NOT NULL DEFAULT 'PENDING',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (shop_domain) REFERENCES merchants(shop_domain) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_payment_sessions_shop_domain ON payment_sessions(shop_domain);
CREATE INDEX IF NOT EXISTS idx_payment_sessions_kashcash_tx ON payment_sessions(kashcash_transaction_id);

CREATE TABLE IF NOT EXISTS refund_sessions (
  shopify_refund_id TEXT PRIMARY KEY,
  shopify_gid TEXT NOT NULL,
  payment_session_id TEXT NOT NULL,
  shop_domain TEXT NOT NULL,
  amount REAL NOT NULL,
  currency TEXT NOT NULL,
  kashcash_refund_transaction_id TEXT,
  status TEXT NOT NULL DEFAULT 'PENDING',
  error_message TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (shop_domain) REFERENCES merchants(shop_domain) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_refund_sessions_payment_session ON refund_sessions(payment_session_id);
`;

export const MIGRATIONS_DOWN = `
DROP TABLE IF EXISTS refund_sessions;
DROP TABLE IF EXISTS payment_sessions;
DROP TABLE IF EXISTS oauth_states;
DROP TABLE IF EXISTS merchants;
`;

export class KashCashRepository {
  private readonly db: Database.Database;
  private readonly encryptionKey: string;

  constructor(dbPath: string, encryptionKey: string) {
    if (dbPath !== ':memory:') {
      const dir = path.dirname(dbPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    }

    this.db = new Database(dbPath);
    this.encryptionKey = encryptionKey;

    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.db.pragma('busy_timeout = 5000');

    this.migrateUp();
  }

  public migrateUp(): void {
    this.db.exec(MIGRATIONS_UP);
  }

  public migrateDown(): void {
    this.db.exec(MIGRATIONS_DOWN);
  }

  public ping(): boolean {
    const row = this.db.prepare('SELECT 1 AS ok').get() as { ok: number } | undefined;
    return row?.ok === 1;
  }

  public close(): void {
    this.db.close();
  }

  // ==========================================================================
  // OAuth State Management
  // ==========================================================================
  public saveOAuthState(state: string, shopDomain: string, ttlSeconds = 600): void {
    const now = Date.now();
    this.db.prepare('DELETE FROM oauth_states WHERE expires_at < ?').run(now);
    this.db
      .prepare('INSERT INTO oauth_states (state, shop_domain, expires_at) VALUES (?, ?, ?)')
      .run(state, shopDomain, now + ttlSeconds * 1000);
  }

  public consumeOAuthState(state: string, shopDomain: string): boolean {
    const now = Date.now();
    const txn = this.db.transaction(() => {
      const row = this.db
        .prepare('SELECT shop_domain, expires_at FROM oauth_states WHERE state = ?')
        .get(state) as { shop_domain: string; expires_at: number } | undefined;

      this.db.prepare('DELETE FROM oauth_states WHERE state = ?').run(state);

      if (!row) {
        return false;
      }
      return row.shop_domain === shopDomain && row.expires_at >= now;
    });
    return txn();
  }

  // ==========================================================================
  // Merchant Management
  // ==========================================================================
  public upsertMerchantOAuth(shopDomain: string, accessToken: string): MerchantRecord {
    const now = new Date().toISOString();
    const encryptedAccessToken = encryptSecret(accessToken, this.encryptionKey);

    this.db
      .prepare(
        `INSERT INTO merchants (
          shop_domain, access_token_encrypted, installed_at, updated_at
        ) VALUES (?, ?, ?, ?)
        ON CONFLICT(shop_domain) DO UPDATE SET
          access_token_encrypted = excluded.access_token_encrypted,
          updated_at = excluded.updated_at`
      )
      .run(shopDomain, encryptedAccessToken, now, now);

    const record = this.getMerchant(shopDomain);
    if (!record) {
      throw new Error(`Failed to retrieve merchant after upsert: ${shopDomain}`);
    }
    return record;
  }

  public updateMerchantKashCashCredentials(params: {
    shopDomain: string;
    businessId: string;
    merchantToken: string;
    testMode: boolean;
    isConfigured: boolean;
  }): MerchantRecord {
    const now = new Date().toISOString();
    const encryptedMerchantToken = encryptSecret(params.merchantToken, this.encryptionKey);

    const result = this.db
      .prepare(
        `UPDATE merchants
         SET business_id = ?,
             merchant_token_encrypted = ?,
             test_mode = ?,
             is_configured = ?,
             updated_at = ?
         WHERE shop_domain = ?`
      )
      .run(
        params.businessId.trim(),
        encryptedMerchantToken,
        params.testMode ? 1 : 0,
        params.isConfigured ? 1 : 0,
        now,
        params.shopDomain
      );

    if (result.changes === 0) {
      throw new Error(`Merchant not found: ${params.shopDomain}`);
    }

    const updated = this.getMerchant(params.shopDomain);
    if (!updated) {
      throw new Error(`Failed to fetch updated merchant: ${params.shopDomain}`);
    }
    return updated;
  }

  public getMerchant(shopDomain: string): MerchantRecord | null {
    const row = this.db
      .prepare(
        `SELECT shop_domain, access_token_encrypted, business_id, merchant_token_encrypted,
                test_mode, is_configured, installed_at, updated_at
         FROM merchants
         WHERE shop_domain = ?`
      )
      .get(shopDomain) as RawMerchantRow | undefined;

    if (!row) {
      return null;
    }

    return {
      shopDomain: row.shop_domain,
      accessToken: decryptSecret(row.access_token_encrypted, this.encryptionKey),
      businessId: row.business_id,
      merchantToken: row.merchant_token_encrypted
        ? decryptSecret(row.merchant_token_encrypted, this.encryptionKey)
        : null,
      testMode: row.test_mode === 1,
      isConfigured: row.is_configured === 1,
      installedAt: row.installed_at,
      updatedAt: row.updated_at,
    };
  }

  public deleteMerchant(shopDomain: string): void {
    this.db.prepare('DELETE FROM merchants WHERE shop_domain = ?').run(shopDomain);
  }

  // ==========================================================================
  // Payment Sessions
  // ==========================================================================
  /**
   * Generates a cryptographically random 12-digit integer orderId (100,000,000,000 - 999,999,999,999)
   * so external callers cannot guess or enumerate order IDs or infer store transaction volume.
   */
  private generateUniqueOrderId(): number {
    for (let attempt = 0; attempt < 10; attempt++) {
      const candidate = crypto.randomInt(100_000_000_000, 999_999_999_999);
      const exists = this.db
        .prepare('SELECT 1 FROM payment_sessions WHERE order_id = ?')
        .get(candidate);
      if (!exists) {
        return candidate;
      }
    }
    throw new Error('Failed to generate unique random orderId');
  }

  public createOrGetPaymentSession(input: CreatePaymentSessionInput): PaymentSessionRecord {
    const existing = this.getPaymentSessionByShopifyId(input.shopifySessionId);
    if (existing) {
      return existing;
    }

    const now = new Date().toISOString();
    const orderId = this.generateUniqueOrderId();

    this.db
      .prepare(
        `INSERT INTO payment_sessions (
          order_id, shopify_session_id, shopify_gid, shop_domain, amount, currency,
          test_mode, order_key, cancel_url, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)`
      )
      .run(
        orderId,
        input.shopifySessionId,
        input.shopifyGid,
        input.shopDomain,
        input.amount,
        input.currency,
        input.testMode ? 1 : 0,
        input.orderKey,
        input.cancelUrl,
        now,
        now
      );

    const created = this.getPaymentSessionByOrderId(orderId);
    if (!created) {
      throw new Error('Failed to load created payment session');
    }
    return created;
  }

  public getPaymentSessionByOrderId(orderId: number): PaymentSessionRecord | null {
    const row = this.db
      .prepare(
        `SELECT order_id, shopify_session_id, shopify_gid, shop_domain, amount, currency,
                test_mode, order_key, cancel_url, redirect_url, kashcash_transaction_id,
                status, created_at, updated_at
         FROM payment_sessions
         WHERE order_id = ?`
      )
      .get(orderId) as RawPaymentSessionRow | undefined;

    return row ? this.mapPaymentSessionRow(row) : null;
  }

  public getPaymentSessionByShopifyId(shopifySessionId: string): PaymentSessionRecord | null {
    const row = this.db
      .prepare(
        `SELECT order_id, shopify_session_id, shopify_gid, shop_domain, amount, currency,
                test_mode, order_key, cancel_url, redirect_url, kashcash_transaction_id,
                status, created_at, updated_at
         FROM payment_sessions
         WHERE shopify_session_id = ?`
      )
      .get(shopifySessionId) as RawPaymentSessionRow | undefined;

    return row ? this.mapPaymentSessionRow(row) : null;
  }

  public getPaymentSessionByKashCashTransactionId(
    kashcashTransactionId: string
  ): PaymentSessionRecord | null {
    const row = this.db
      .prepare(
        `SELECT order_id, shopify_session_id, shopify_gid, shop_domain, amount, currency,
                test_mode, order_key, cancel_url, redirect_url, kashcash_transaction_id,
                status, created_at, updated_at
         FROM payment_sessions
         WHERE kashcash_transaction_id = ?`
      )
      .get(kashcashTransactionId) as RawPaymentSessionRow | undefined;

    return row ? this.mapPaymentSessionRow(row) : null;
  }

  public updatePaymentSessionStatus(params: {
    orderId: number;
    status: PaymentSessionStatus;
    kashcashTransactionId?: string;
    redirectUrl?: string | null;
  }): PaymentSessionRecord {
    const now = new Date().toISOString();
    this.db
      .prepare(
        `UPDATE payment_sessions
         SET status = ?,
             kashcash_transaction_id = COALESCE(?, kashcash_transaction_id),
             redirect_url = COALESCE(?, redirect_url),
             updated_at = ?
         WHERE order_id = ?`
      )
      .run(
        params.status,
        params.kashcashTransactionId ?? null,
        params.redirectUrl ?? null,
        now,
        params.orderId
      );

    const updated = this.getPaymentSessionByOrderId(params.orderId);
    if (!updated) {
      throw new Error(`Payment session not found for orderId ${params.orderId}`);
    }
    return updated;
  }

  private mapPaymentSessionRow(row: RawPaymentSessionRow): PaymentSessionRecord {
    return {
      orderId: row.order_id,
      shopifySessionId: row.shopify_session_id,
      shopifyGid: row.shopify_gid,
      shopDomain: row.shop_domain,
      amount: row.amount,
      currency: row.currency,
      testMode: row.test_mode === 1,
      orderKey: row.order_key,
      cancelUrl: row.cancel_url,
      redirectUrl: row.redirect_url,
      kashcashTransactionId: row.kashcash_transaction_id,
      status: row.status,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  // ==========================================================================
  // Refund Sessions
  // ==========================================================================
  public createOrGetRefundSession(input: CreateRefundSessionInput): RefundSessionRecord {
    const existing = this.getRefundSession(input.shopifyRefundId);
    if (existing) {
      return existing;
    }

    const now = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO refund_sessions (
          shopify_refund_id, shopify_gid, payment_session_id, shop_domain,
          amount, currency, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)`
      )
      .run(
        input.shopifyRefundId,
        input.shopifyGid,
        input.paymentSessionId,
        input.shopDomain,
        input.amount,
        input.currency,
        now,
        now
      );

    const created = this.getRefundSession(input.shopifyRefundId);
    if (!created) {
      throw new Error('Failed to load created refund session');
    }
    return created;
  }

  public getRefundSession(shopifyRefundId: string): RefundSessionRecord | null {
    const row = this.db
      .prepare(
        `SELECT shopify_refund_id, shopify_gid, payment_session_id, shop_domain,
                amount, currency, kashcash_refund_transaction_id, status,
                error_message, created_at, updated_at
         FROM refund_sessions
         WHERE shopify_refund_id = ?`
      )
      .get(shopifyRefundId) as RawRefundSessionRow | undefined;

    if (!row) {
      return null;
    }

    return {
      shopifyRefundId: row.shopify_refund_id,
      shopifyGid: row.shopify_gid,
      paymentSessionId: row.payment_session_id,
      shopDomain: row.shop_domain,
      amount: row.amount,
      currency: row.currency,
      kashcashRefundTransactionId: row.kashcash_refund_transaction_id,
      status: row.status,
      errorMessage: row.error_message,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  public getTotalRefundedAmount(paymentSessionId: string, excludeRefundId?: string): number {
    const row = excludeRefundId
      ? (this.db
          .prepare(
            `SELECT COALESCE(SUM(amount), 0) AS total
             FROM refund_sessions
             WHERE payment_session_id = ? AND status = 'RESOLVED' AND shopify_refund_id != ?`
          )
          .get(paymentSessionId, excludeRefundId) as { total: number })
      : (this.db
          .prepare(
            `SELECT COALESCE(SUM(amount), 0) AS total
             FROM refund_sessions
             WHERE payment_session_id = ? AND status = 'RESOLVED'`
          )
          .get(paymentSessionId) as { total: number });

    return Number(row?.total ?? 0);
  }

  public updateRefundSessionStatus(params: {
    shopifyRefundId: string;
    status: RefundSessionStatus;
    kashcashRefundTransactionId?: string | null;
    errorMessage?: string | null;
  }): RefundSessionRecord {
    const now = new Date().toISOString();
    this.db
      .prepare(
        `UPDATE refund_sessions
         SET status = ?,
             kashcash_refund_transaction_id = COALESCE(?, kashcash_refund_transaction_id),
             error_message = COALESCE(?, error_message),
             updated_at = ?
         WHERE shopify_refund_id = ?`
      )
      .run(
        params.status,
        params.kashcashRefundTransactionId ?? null,
        params.errorMessage ?? null,
        now,
        params.shopifyRefundId
      );

    const updated = this.getRefundSession(params.shopifyRefundId);
    if (!updated) {
      throw new Error(`Refund session not found: ${params.shopifyRefundId}`);
    }
    return updated;
  }
}
