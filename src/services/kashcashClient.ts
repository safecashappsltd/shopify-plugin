import { AppConfig } from '../config/env.js';
import { logger } from '../utils/logger.js';

export interface VerifyTransactionInput {
  transactionId: string;
  merchantToken: string;
  testMode: boolean;
}

export interface RefundTransactionInput {
  transactionId: string;
  businessId: string;
  merchantToken: string;
  amount: number;
  externalRefundId: string;
  testMode: boolean;
}

export interface RefundTransactionResult {
  success: boolean;
  refundTransactionId?: string;
  errorCode?: string;
  errorMessage?: string;
}

export interface CancelTransactionInput {
  transactionId: string;
  businessId: string;
  merchantToken: string;
  testMode: boolean;
}

export class KashCashClient {
  private readonly appConfig: AppConfig;
  private readonly fetchFn: typeof fetch;

  constructor(appConfig: AppConfig, fetchFn: typeof fetch = globalThis.fetch) {
    this.appConfig = appConfig;
    this.fetchFn = fetchFn;
  }

  /**
   * Resolves the KashCash API base URL based on APP_ENV ('dev' vs 'prod') and session/merchant testMode.
   * - If APP_ENV === 'dev' OR testMode === true -> KASHCASH_STAGE_API_URL (https://stage-api.safecashapps.com)
   * - If APP_ENV === 'prod' AND testMode === false -> KASHCASH_PROD_API_URL (https://prod-api.safecashapps.com)
   */
  public getApiBaseUrl(testMode: boolean): string {
    const useStage = this.appConfig.APP_ENV === 'dev' || testMode;
    const base = useStage
      ? this.appConfig.KASHCASH_STAGE_API_URL
      : this.appConfig.KASHCASH_PROD_API_URL;
    return base.replace(/\/+$/, '');
  }

  /**
   * Builds the KashCash E-Commerce payment page redirect URL.
   * Note: `baseUrl` includes `/wp-json` (matching WooCommerce plugin & cashi-server ExternalController expectations).
   */
  public buildPaymentPageUrl(orderId: number, testMode: boolean): string {
    const apiBase = this.getApiBaseUrl(testMode);
    const appUrl = new URL(this.appConfig.APP_BASE_URL);
    const baseUrlParam = `${appUrl.host}/wp-json`;

    const params = new URLSearchParams({
      orderId: String(orderId),
      baseUrl: baseUrlParam,
    });

    return `${apiBase}/api/external/v1/ecommerce/payment/page/?${params.toString()}`;
  }

  /**
   * Calls `POST /api/external/v1/ecommerce/transaction/status/` on KashCash server
   * to confirm that the transaction is genuinely completed (`{ completed: true }`).
   */
  public async verifyTransactionCompleted(input: VerifyTransactionInput): Promise<boolean> {
    const apiBase = this.getApiBaseUrl(input.testMode);
    const url = `${apiBase}/api/external/v1/ecommerce/transaction/status/`;

    const response = await this.fetchWithRetry(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        transactionId: input.transactionId,
        MerchantToken: input.merchantToken,
      }),
    });

    if (!response.ok) {
      logger.error(
        { status: response.status, transactionId: input.transactionId },
        'KashCash transaction status verification returned non-OK status'
      );
      return false;
    }

    const data = (await response.json()) as { completed?: boolean };
    return data?.completed === true;
  }

  /**
   * Initiates a refund via `POST /api/external/v1.0/transactions/refund` using the merchant's API key (`x-api-key`).
   */
  public async refundTransaction(input: RefundTransactionInput): Promise<RefundTransactionResult> {
    const apiBase = this.getApiBaseUrl(input.testMode);
    const url = `${apiBase}/api/external/v1.0/transactions/refund`;

    try {
      const response = await this.fetchWithRetry(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'x-api-key': input.merchantToken,
          'X-Business-Id': input.businessId,
        },
        body: JSON.stringify({
          BusinessId: input.businessId,
          TransactionId: input.transactionId,
          Amount: Math.abs(input.amount),
          ExternalId: input.externalRefundId,
          AllowQrScanning: false,
          Comments: `Shopify refund ${input.externalRefundId}`,
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        logger.error(
          {
            status: response.status,
            transactionId: input.transactionId,
            externalRefundId: input.externalRefundId,
            errorText,
          },
          'KashCash refund request failed'
        );
        return {
          success: false,
          errorCode: `HTTP_${response.status}`,
          errorMessage: errorText || `Refund failed with status ${response.status}`,
        };
      }

      const body = (await response.json()) as {
        transactionId?: string;
        TransactionId?: string;
        transactionStatus?: number;
        TransactionStatus?: number;
      };

      const refundTxId = body.transactionId ?? body.TransactionId ?? input.externalRefundId;
      return {
        success: true,
        refundTransactionId: refundTxId,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown refund network error';
      logger.error({ err, transactionId: input.transactionId }, 'Exception during KashCash refund');
      return {
        success: false,
        errorCode: 'NETWORK_ERROR',
        errorMessage: message,
      };
    }
  }

  /**
   * Cancels a pending KashCash payment request (`POST /api/external/v1.0/request/cancel`).
   */
  public async cancelTransaction(input: CancelTransactionInput): Promise<boolean> {
    const apiBase = this.getApiBaseUrl(input.testMode);
    const url = `${apiBase}/api/external/v1.0/request/cancel`;

    try {
      const response = await this.fetchWithRetry(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': input.merchantToken,
          'X-Business-Id': input.businessId,
        },
        body: JSON.stringify({
          BusinessId: input.businessId,
          TransactionId: input.transactionId,
        }),
      });
      return response.ok;
    } catch (err) {
      logger.error({ err, transactionId: input.transactionId }, 'Failed to cancel KashCash transaction');
      return false;
    }
  }

  private async fetchWithRetry(
    url: string,
    init: RequestInit,
    maxAttempts = 3
  ): Promise<Response> {
    let lastError: unknown;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const response = await this.fetchFn(url, {
          ...init,
          signal: AbortSignal.timeout(this.appConfig.KASHCASH_HTTP_TIMEOUT_MS),
        });

        if (response.status >= 500 && attempt < maxAttempts) {
          await this.delayWithJitter(attempt);
          continue;
        }
        return response;
      } catch (err) {
        lastError = err;
        if (attempt < maxAttempts) {
          await this.delayWithJitter(attempt);
        }
      }
    }
    throw lastError instanceof Error ? lastError : new Error('Failed to fetch from KashCash API');
  }

  private async delayWithJitter(attempt: number): Promise<void> {
    if (this.appConfig.NODE_ENV === 'test') {
      return;
    }
    const baseMs = Math.min(200 * Math.pow(2, attempt - 1), 2000);
    const jitterMs = Math.floor(Math.random() * 100);
    await new Promise((resolve) => setTimeout(resolve, baseMs + jitterMs));
  }
}
