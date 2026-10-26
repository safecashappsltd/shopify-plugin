import { AppConfig } from '../config/env.js';
import { isValidShopDomain } from '../security/crypto.js';
import { logger } from '../utils/logger.js';

export interface ResolvePaymentSessionResult {
  redirectUrl: string;
}

export interface RejectPaymentSessionResult {
  redirectUrl: string;
}

const PAYMENT_SESSION_RESOLVE_MUTATION = `
mutation paymentSessionResolve($id: ID!) {
  paymentSessionResolve(id: $id) {
    paymentSession {
      id
      state {
        ... on PaymentSessionStateResolved {
          code
        }
      }
      nextAction {
        action
        context {
          ... on PaymentSessionActionsRedirect {
            redirectUrl
          }
        }
      }
    }
    userErrors {
      field
      message
    }
  }
}
`;

const PAYMENT_SESSION_REJECT_MUTATION = `
mutation paymentSessionReject($id: ID!, $reason: PaymentSessionRejectionReasonInput!) {
  paymentSessionReject(id: $id, reason: $reason) {
    paymentSession {
      id
      state {
        ... on PaymentSessionStateRejected {
          code
          reason
        }
      }
      nextAction {
        action
        context {
          ... on PaymentSessionActionsRedirect {
            redirectUrl
          }
        }
      }
    }
    userErrors {
      field
      message
    }
  }
}
`;

const REFUND_SESSION_RESOLVE_MUTATION = `
mutation refundSessionResolve($id: ID!) {
  refundSessionResolve(id: $id) {
    refundSession {
      id
      state {
        ... on RefundSessionStateResolved {
          code
        }
      }
    }
    userErrors {
      field
      message
    }
  }
}
`;

const REFUND_SESSION_REJECT_MUTATION = `
mutation refundSessionReject($id: ID!, $reason: RefundSessionRejectionReasonInput!) {
  refundSessionReject(id: $id, reason: $reason) {
    refundSession {
      id
      state {
        ... on RefundSessionStateRejected {
          code
          reason
        }
      }
    }
    userErrors {
      field
      message
    }
  }
}
`;

const CAPTURE_SESSION_RESOLVE_MUTATION = `
mutation captureSessionResolve($id: ID!) {
  captureSessionResolve(id: $id) {
    captureSession {
      id
    }
    userErrors {
      field
      message
    }
  }
}
`;

const VOID_SESSION_RESOLVE_MUTATION = `
mutation voidSessionResolve($id: ID!) {
  voidSessionResolve(id: $id) {
    voidSession {
      id
    }
    userErrors {
      field
      message
    }
  }
}
`;

const PAYMENTS_APPS_CONFIGURE_MUTATION = `
mutation paymentsAppsConfigure($externalHandle: String!, $ready: Boolean!) {
  paymentsAppsConfigure(externalHandle: $externalHandle, ready: $ready) {
    paymentsAppConfiguration {
      externalHandle
      ready
    }
    userErrors {
      field
      message
    }
  }
}
`;

export class ShopifyPaymentsClient {
  private readonly appConfig: AppConfig;
  private readonly fetchFn: typeof fetch;

  constructor(appConfig: AppConfig, fetchFn: typeof fetch = globalThis.fetch) {
    this.appConfig = appConfig;
    this.fetchFn = fetchFn;
  }

  /**
   * Resolves a Shopify Payment Session via `paymentSessionResolve` and returns Shopify's `redirectUrl`.
   */
  public async resolvePaymentSession(params: {
    shopDomain: string;
    accessToken: string;
    shopifyGid: string;
  }): Promise<ResolvePaymentSessionResult> {
    const data = await this.executeGraphQL<{
      paymentSessionResolve?: {
        paymentSession?: {
          nextAction?: {
            context?: {
              redirectUrl?: string;
            };
          };
        };
        userErrors?: Array<{ field?: string[]; message: string }>;
      };
    }>({
      shopDomain: params.shopDomain,
      accessToken: params.accessToken,
      query: PAYMENT_SESSION_RESOLVE_MUTATION,
      variables: { id: params.shopifyGid },
    });

    const payload = data.paymentSessionResolve;
    if (payload?.userErrors && payload.userErrors.length > 0) {
      const msg = payload.userErrors.map((e) => e.message).join('; ');
      throw new Error(`Shopify paymentSessionResolve userErrors: ${msg}`);
    }

    const redirectUrl = payload?.paymentSession?.nextAction?.context?.redirectUrl;
    if (!redirectUrl) {
      throw new Error('Shopify paymentSessionResolve did not return a redirectUrl');
    }

    return { redirectUrl };
  }

  /**
   * Rejects a Shopify Payment Session via `paymentSessionReject` and returns Shopify's `redirectUrl`.
   */
  public async rejectPaymentSession(params: {
    shopDomain: string;
    accessToken: string;
    shopifyGid: string;
    merchantMessage: string;
    reasonCode?: 'PROCESSING_ERROR' | 'RISKY' | 'AUTHENTICATION_FAILED';
  }): Promise<RejectPaymentSessionResult> {
    const data = await this.executeGraphQL<{
      paymentSessionReject?: {
        paymentSession?: {
          nextAction?: {
            context?: {
              redirectUrl?: string;
            };
          };
        };
        userErrors?: Array<{ field?: string[]; message: string }>;
      };
    }>({
      shopDomain: params.shopDomain,
      accessToken: params.accessToken,
      query: PAYMENT_SESSION_REJECT_MUTATION,
      variables: {
        id: params.shopifyGid,
        reason: {
          code: params.reasonCode ?? 'PROCESSING_ERROR',
          merchantMessage: params.merchantMessage,
        },
      },
    });

    const payload = data.paymentSessionReject;
    if (payload?.userErrors && payload.userErrors.length > 0) {
      const msg = payload.userErrors.map((e) => e.message).join('; ');
      throw new Error(`Shopify paymentSessionReject userErrors: ${msg}`);
    }

    const redirectUrl = payload?.paymentSession?.nextAction?.context?.redirectUrl ?? '';
    return { redirectUrl };
  }

  /**
   * Resolves a Shopify Refund Session (`refundSessionResolve`).
   */
  public async resolveRefundSession(params: {
    shopDomain: string;
    accessToken: string;
    shopifyGid: string;
  }): Promise<void> {
    const data = await this.executeGraphQL<{
      refundSessionResolve?: {
        userErrors?: Array<{ field?: string[]; message: string }>;
      };
    }>({
      shopDomain: params.shopDomain,
      accessToken: params.accessToken,
      query: REFUND_SESSION_RESOLVE_MUTATION,
      variables: { id: params.shopifyGid },
    });

    const userErrors = data.refundSessionResolve?.userErrors;
    if (userErrors && userErrors.length > 0) {
      throw new Error(`Shopify refundSessionResolve userErrors: ${userErrors.map((e) => e.message).join('; ')}`);
    }
  }

  /**
   * Rejects a Shopify Refund Session (`refundSessionReject`).
   */
  public async rejectRefundSession(params: {
    shopDomain: string;
    accessToken: string;
    shopifyGid: string;
    merchantMessage: string;
  }): Promise<void> {
    const data = await this.executeGraphQL<{
      refundSessionReject?: {
        userErrors?: Array<{ field?: string[]; message: string }>;
      };
    }>({
      shopDomain: params.shopDomain,
      accessToken: params.accessToken,
      query: REFUND_SESSION_REJECT_MUTATION,
      variables: {
        id: params.shopifyGid,
        reason: {
          code: 'PROCESSING_ERROR',
          merchantMessage: params.merchantMessage,
        },
      },
    });

    const userErrors = data.refundSessionReject?.userErrors;
    if (userErrors && userErrors.length > 0) {
      throw new Error(`Shopify refundSessionReject userErrors: ${userErrors.map((e) => e.message).join('; ')}`);
    }
  }

  /**
   * Resolves a Capture Session (`captureSessionResolve`).
   */
  public async resolveCaptureSession(params: {
    shopDomain: string;
    accessToken: string;
    shopifyGid: string;
  }): Promise<void> {
    await this.executeGraphQL({
      shopDomain: params.shopDomain,
      accessToken: params.accessToken,
      query: CAPTURE_SESSION_RESOLVE_MUTATION,
      variables: { id: params.shopifyGid },
    });
  }

  /**
   * Resolves a Void Session (`voidSessionResolve`).
   */
  public async resolveVoidSession(params: {
    shopDomain: string;
    accessToken: string;
    shopifyGid: string;
  }): Promise<void> {
    await this.executeGraphQL({
      shopDomain: params.shopDomain,
      accessToken: params.accessToken,
      query: VOID_SESSION_RESOLVE_MUTATION,
      variables: { id: params.shopifyGid },
    });
  }

  /**
   * Configures the merchant's Payments App readiness via `paymentsAppsConfigure`.
   */
  public async configurePaymentsApp(params: {
    shopDomain: string;
    accessToken: string;
    externalHandle: string;
    ready: boolean;
  }): Promise<void> {
    const data = await this.executeGraphQL<{
      paymentsAppsConfigure?: {
        userErrors?: Array<{ field?: string[]; message: string }>;
      };
    }>({
      shopDomain: params.shopDomain,
      accessToken: params.accessToken,
      query: PAYMENTS_APPS_CONFIGURE_MUTATION,
      variables: {
        externalHandle: params.externalHandle,
        ready: params.ready,
      },
    });

    const userErrors = data.paymentsAppsConfigure?.userErrors;
    if (userErrors && userErrors.length > 0) {
      throw new Error(`Shopify paymentsAppsConfigure userErrors: ${userErrors.map((e) => e.message).join('; ')}`);
    }
  }

  /**
   * Exchanges a temporary Shopify OAuth authorization code for a permanent offline access token.
   */
  public async exchangeOAuthCodeForToken(params: {
    shopDomain: string;
    code: string;
  }): Promise<string> {
    if (!isValidShopDomain(params.shopDomain)) {
      throw new Error(`Invalid shop domain: ${params.shopDomain}`);
    }

    const url = `https://${params.shopDomain}/admin/oauth/access_token`;
    const response = await this.fetchFn(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        client_id: this.appConfig.SHOPIFY_API_KEY,
        client_secret: this.appConfig.SHOPIFY_API_SECRET,
        code: params.code,
      }),
      signal: AbortSignal.timeout(this.appConfig.SHOPIFY_HTTP_TIMEOUT_MS),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Failed to exchange Shopify OAuth code (HTTP ${response.status}): ${text}`);
    }

    const body = (await response.json()) as { access_token?: string };
    if (!body.access_token) {
      throw new Error('Shopify OAuth response did not include access_token');
    }

    return body.access_token;
  }

  private async executeGraphQL<TData>(params: {
    shopDomain: string;
    accessToken: string;
    query: string;
    variables: Record<string, unknown>;
  }): Promise<TData> {
    if (!isValidShopDomain(params.shopDomain)) {
      throw new Error(`Invalid Shopify shopDomain: ${params.shopDomain}`);
    }

    const endpoint = `https://${params.shopDomain}/payments_apps/api/${this.appConfig.SHOPIFY_API_VERSION}/graphql.json`;

    let lastError: unknown;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const response = await this.fetchFn(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
            'X-Shopify-Access-Token': params.accessToken,
          },
          body: JSON.stringify({
            query: params.query,
            variables: params.variables,
          }),
          signal: AbortSignal.timeout(this.appConfig.SHOPIFY_HTTP_TIMEOUT_MS),
        });

        if ((response.status === 429 || response.status >= 500) && attempt < 3) {
          logger.warn(
            { status: response.status, shopDomain: params.shopDomain, attempt },
            'Transient Shopify GraphQL error, retrying'
          );
          if (this.appConfig.NODE_ENV !== 'test') {
            await new Promise((r) => setTimeout(r, 300 * attempt));
          }
          continue;
        }

        if (!response.ok) {
          const text = await response.text();
          throw new Error(`Shopify GraphQL HTTP ${response.status}: ${text}`);
        }

        const json = (await response.json()) as {
          data?: TData;
          errors?: Array<{ message: string }>;
        };

        if (json.errors && json.errors.length > 0) {
          throw new Error(`Shopify GraphQL errors: ${json.errors.map((e) => e.message).join('; ')}`);
        }

        if (!json.data) {
          throw new Error('Shopify GraphQL response missing data object');
        }

        return json.data;
      } catch (err) {
        lastError = err;
        if (attempt < 3 && this.appConfig.NODE_ENV !== 'test') {
          await new Promise((r) => setTimeout(r, 300 * attempt));
        }
      }
    }

    throw lastError instanceof Error ? lastError : new Error('Shopify GraphQL request failed');
  }
}
