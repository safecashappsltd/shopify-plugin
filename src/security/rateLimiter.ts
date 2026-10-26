import { NextFunction, Request, Response } from 'express';

export interface RateLimiterOptions {
  windowMs: number;
  maxRequests: number;
}

interface BucketEntry {
  count: number;
  resetAt: number;
}

/**
 * In-memory sliding-window IP rate limiter middleware to protect payment & auth endpoints
 * from brute-force, enumeration, and DoS attacks.
 */
export function createRateLimiter(options: RateLimiterOptions) {
  const { windowMs, maxRequests } = options;
  const buckets = new Map<string, BucketEntry>();

  return (req: Request, res: Response, next: NextFunction): void => {
    const now = Date.now();
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';

    // Periodic cleanup of expired buckets to prevent unbounded memory growth
    if (buckets.size > 5000) {
      for (const [key, entry] of buckets.entries()) {
        if (entry.resetAt <= now) {
          buckets.delete(key);
        }
      }
    }

    const existing = buckets.get(clientIp);
    if (!existing || existing.resetAt <= now) {
      buckets.set(clientIp, { count: 1, resetAt: now + windowMs });
      next();
      return;
    }

    existing.count += 1;
    if (existing.count > maxRequests) {
      const retryAfterSec = Math.max(1, Math.ceil((existing.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfterSec));
      res.status(429).json({
        error: 'Too many requests, please try again later',
        code: 'RATE_LIMIT_EXCEEDED',
      });
      return;
    }

    next();
  };
}
