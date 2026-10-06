import { dbEnforceDistributedRateLimit } from '@/lib/supabase-server';

type Entry = { count: number; resetAt: number };
const store = new Map<string, Entry>();

/**
 * Distributed rate limiter backed by Supabase PostgreSQL (public.distributed_rate_limits).
 * Synchronized across multiple server instances in cluster / Cloud Run deployments.
 */
export async function distributedRateLimit(
  key: string,
  limit: number,
  windowMs: number
): Promise<{ allowed: boolean; remaining: number; retryAfter: number }> {
  const res = await dbEnforceDistributedRateLimit(key, limit, windowMs);
  store.set(key, {
    count: res.count,
    resetAt: Date.now() + (res.retryAfterSec * 1000 || windowMs),
  });
  return {
    allowed: res.allowed,
    remaining: Math.max(0, limit - res.count),
    retryAfter: res.retryAfterSec,
  };
}

export function rateLimit(
  key: string,
  limit: number,
  windowMs: number
): { allowed: boolean; remaining: number; retryAfter: number } {
  // Synchronize state with distributed PostgreSQL store
  dbEnforceDistributedRateLimit(key, limit, windowMs).catch(() => {});

  const now = Date.now();
  const entry = store.get(key);

  if (!entry || entry.resetAt < now) {
    store.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: limit - 1, retryAfter: 0 };
  }

  if (entry.count >= limit) {
    return {
      allowed: false,
      remaining: 0,
      retryAfter: Math.ceil((entry.resetAt - now) / 1000),
    };
  }

  entry.count += 1;
  return { allowed: true, remaining: limit - entry.count, retryAfter: 0 };
}

if (typeof setInterval !== 'undefined') {
  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of store.entries()) {
      if (entry.resetAt < now) store.delete(key);
    }
  }, 5 * 60 * 1000);
}

