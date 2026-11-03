/**
 * In-memory LRU / TTL Cache and Rate Limiter
 */

interface CacheEntry<T> {
  data: T;
  expiresAt: number;
}

export class SimpleTTLCache<T> {
  private store = new Map<string, CacheEntry<T>>();
  private maxItems: number;

  constructor(maxItems = 1000) {
    this.maxItems = maxItems;
  }

  get(key: string): T | null {
    const entry = this.store.get(key);
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }

    return entry.data;
  }

  set(key: string, data: T, ttlMs: number): void {
    if (this.store.size >= this.maxItems) {
      // Evict the first/oldest item
      const firstKey = this.store.keys().next().value;
      if (firstKey) this.store.delete(firstKey);
    }

    this.store.set(key, {
      data,
      expiresAt: Date.now() + ttlMs
    });
  }

  clear(): void {
    this.store.clear();
  }
}

interface ClientRateRecord {
  count: number;
  resetAt: number;
}

export class SimpleRateLimiter {
  private clients = new Map<string, ClientRateRecord>();
  private windowMs: number;
  private maxRequests: number;

  constructor(windowMs = 60000, maxRequests = 40) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
  }

  check(ip: string): { allowed: boolean; remaining: number; retryAfterSec?: number } {
    const now = Date.now();
    const record = this.clients.get(ip);

    if (!record || now > record.resetAt) {
      this.clients.set(ip, {
        count: 1,
        resetAt: now + this.windowMs
      });
      return { allowed: true, remaining: this.maxRequests - 1 };
    }

    if (record.count >= this.maxRequests) {
      const retryAfterSec = Math.ceil((record.resetAt - now) / 1000);
      return { allowed: false, remaining: 0, retryAfterSec };
    }

    record.count++;
    return { allowed: true, remaining: this.maxRequests - record.count };
  }

  cleanup(): void {
    const now = Date.now();
    for (const [ip, record] of this.clients.entries()) {
      if (now > record.resetAt) {
        this.clients.delete(ip);
      }
    }
  }
}
