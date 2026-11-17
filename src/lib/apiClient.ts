/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ensec ERP - Centralized Frontend API Client & Authenticated Database Gateway Adapter
 * All ERP authentication, database operations, and real-time subscriptions communicate
 * exclusively with the Express backend over HttpOnly session cookies.
 * Zero database URLs, service keys, anon keys, or plaintext credentials exist client-side.
 */

export class ApiError extends Error {
  status: number;
  code?: string;

  constructor(message: string, status: number = 500, code?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

export interface ApiRequestOptions extends RequestInit {
  skipAuthEvent?: boolean;
}

let inMemoryCsrfToken = '';

export function setMemoryCsrfToken(token?: string | null) {
  inMemoryCsrfToken = String(token || '').trim();
}

export function clearMemoryCsrfToken() {
  inMemoryCsrfToken = '';
}

function notifyAuthExpired(url: string) {
  clearMemoryCsrfToken();
  if (typeof window !== 'undefined') {
    window.dispatchEvent(
      new CustomEvent('ensec-auth-expired', {
        detail: { url, status: 401 },
      })
    );
  }
}

function getCsrfTokenFromCookie(): string {
  if (typeof document !== 'undefined' && document.cookie) {
    const pairs = document.cookie.split(';');
    for (const pair of pairs) {
      const idx = pair.indexOf('=');
      if (idx <= 0) continue;
      const k = pair.slice(0, idx).trim();
      if (k === 'ensec_csrf_token') {
        try {
          const decoded = decodeURIComponent(pair.slice(idx + 1).trim());
          if (decoded) return decoded;
        } catch {
          const raw = pair.slice(idx + 1).trim();
          if (raw) return raw;
        }
      }
    }
  }
  return inMemoryCsrfToken;
}

export function getCsrfHeaders(method?: string): Record<string, string> {
  const m = String(method || 'GET').toUpperCase();
  if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return {};
  const token = getCsrfTokenFromCookie();
  return token ? { 'X-CSRF-Token': token } : {};
}

export async function apiRequest<T = any>(
  url: string,
  options: ApiRequestOptions = {}
): Promise<T> {
  const { skipAuthEvent = false, headers: customHeaders, ...rest } = options;

  const headers: Record<string, string> = {
    ...(rest.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    ...getCsrfHeaders(rest.method),
    ...(customHeaders as Record<string, string> | undefined),
  };

  const response = await fetch(url, {
    ...rest,
    credentials: 'include',
    headers,
  });

  const text = await response.text();
  let parsed: any = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { message: text };
    }
  }

  if (response.status === 401 && !skipAuthEvent) {
    notifyAuthExpired(url);
  }

  if (!response.ok) {
    const errMsg =
      parsed?.error?.message ||
      (typeof parsed?.error === 'string' ? parsed.error : '') ||
      parsed?.message ||
      `Request failed with status ${response.status}`;
    const errCode = parsed?.error?.code || parsed?.code || `HTTP_${response.status}`;
    throw new ApiError(errMsg, response.status, errCode);
  }

  return parsed as T;
}

export const apiAuth = {
  async login(identifier: string, password: string) {
    const res = await apiRequest<{
      authenticated: boolean;
      user: any;
      employee?: any;
      expiresAt?: number;
      csrfToken?: string;
      error?: string;
      code?: string;
    }>('/api/auth/login', {
      method: 'POST',
      skipAuthEvent: true,
      body: JSON.stringify({ identifier, password }),
    });
    if (res?.csrfToken) {
      setMemoryCsrfToken(res.csrfToken);
    }
    return res;
  },

  async me() {
    const res = await apiRequest<{
      authenticated: boolean;
      user: any;
      employee?: any;
      csrfToken?: string;
    }>('/api/auth/me', {
      method: 'GET',
      skipAuthEvent: true,
    });
    if (res?.csrfToken) {
      setMemoryCsrfToken(res.csrfToken);
    }
    return res;
  },

  async logout() {
    try {
      return await apiRequest<{ ok: boolean; loggedOut: boolean }>('/api/auth/logout', {
        method: 'POST',
        skipAuthEvent: true,
        body: JSON.stringify({}),
      });
    } finally {
      clearMemoryCsrfToken();
    }
  },

  async changePassword(payload: { currentPassword?: string; newPassword: string }) {
    const res = await apiRequest<{ success: boolean; csrfToken?: string; error?: string }>(
      '/api/auth/change-password',
      {
        method: 'POST',
        body: JSON.stringify(payload),
      }
    );
    if (res?.csrfToken) {
      setMemoryCsrfToken(res.csrfToken);
    }
    return res;
  },

  async resetPassword(payload: {
    identifier: string;
    currentPassword?: string;
    newPassword: string;
  }) {
    return apiRequest<{ success: boolean; error?: string; code?: string }>(
      '/api/auth/reset-password',
      {
        method: 'POST',
        skipAuthEvent: true,
        body: JSON.stringify(payload),
      }
    );
  },
};

export interface DbQueryFilter {
  type: 'eq' | 'neq' | 'in' | 'ilike' | 'gte' | 'or';
  column?: string;
  value?: any;
  expr?: string;
}

export interface DbError {
  message: string;
  code?: string;
  status?: number;
  details?: string;
  hint?: string;
}

export interface DbResult<T = any> {
  data: T | null;
  error: DbError | null;
}

class BackendDbQueryBuilder<T = any> implements PromiseLike<DbResult<T>> {
  private readonly table: string;
  private operation: 'select' | 'insert' | 'upsert' | 'update' | 'delete' = 'select';
  private selectExpr: string = '*';
  private returnSelect: boolean = false;
  private payloadData: any = undefined;
  private writeOptions: { onConflict?: string; ignoreDuplicates?: boolean } | undefined = undefined;
  private filters: DbQueryFilter[] = [];
  private orders: Array<{ column: string; ascending: boolean }> = [];
  private limitCount: number | undefined = undefined;
  private isSingle: boolean = false;
  private isMaybeSingle: boolean = false;
  private execPromise: Promise<DbResult<T>> | null = null;

  constructor(table: string) {
    this.table = table;
  }

  select(columns: string = '*'): this {
    if (this.operation === 'select') {
      this.selectExpr = columns || '*';
    } else {
      this.returnSelect = true;
      if (columns) this.selectExpr = columns;
    }
    return this;
  }

  insert(values: Record<string, any> | Array<Record<string, any>>): this {
    this.operation = 'insert';
    this.payloadData = values;
    return this;
  }

  upsert(
    values: Record<string, any> | Array<Record<string, any>>,
    options?: { onConflict?: string; ignoreDuplicates?: boolean }
  ): this {
    this.operation = 'upsert';
    this.payloadData = values;
    this.writeOptions = options;
    return this;
  }

  update(values: Record<string, any>): this {
    this.operation = 'update';
    this.payloadData = values;
    return this;
  }

  delete(): this {
    this.operation = 'delete';
    return this;
  }

  eq(column: string, value: any): this {
    this.filters.push({ type: 'eq', column, value });
    return this;
  }

  neq(column: string, value: any): this {
    this.filters.push({ type: 'neq', column, value });
    return this;
  }

  in(column: string, values: any[]): this {
    this.filters.push({ type: 'in', column, value: values });
    return this;
  }

  ilike(column: string, pattern: string): this {
    this.filters.push({ type: 'ilike', column, value: pattern });
    return this;
  }

  gte(column: string, value: any): this {
    this.filters.push({ type: 'gte', column, value });
    return this;
  }

  or(expr: string): this {
    this.filters.push({ type: 'or', expr });
    return this;
  }

  order(column: string, opts?: { ascending?: boolean }): this {
    this.orders.push({
      column,
      ascending: opts?.ascending !== false,
    });
    return this;
  }

  limit(count: number): this {
    this.limitCount = count;
    return this;
  }

  single(): this {
    this.isSingle = true;
    return this;
  }

  maybeSingle(): this {
    this.isMaybeSingle = true;
    return this;
  }

  private async execute(): Promise<DbResult<T>> {
    try {
      const response = await fetch(`/api/erp/db/${encodeURIComponent(this.table)}`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          ...getCsrfHeaders('POST'),
        },
        body: JSON.stringify({
          operation: this.operation,
          select: this.selectExpr,
          returnSelect: this.returnSelect,
          payload: this.payloadData,
          options: this.writeOptions,
          filters: this.filters,
          orders: this.orders,
          limit: this.limitCount,
          single: this.isSingle,
          maybeSingle: this.isMaybeSingle,
        }),
      });

      const text = await response.text();
      let parsed: any = null;
      if (text) {
        try {
          parsed = JSON.parse(text);
        } catch {
          parsed = null;
        }
      }

      if (response.status === 401) {
        notifyAuthExpired(`/api/erp/db/${this.table}`);
      }

      if (!response.ok) {
        return {
          data: null,
          error: {
            message:
              parsed?.error?.message ||
              (typeof parsed?.error === 'string' ? parsed.error : '') ||
              `Database gateway error (${response.status})`,
            code: parsed?.error?.code || parsed?.code || `HTTP_${response.status}`,
            status: response.status,
          },
        };
      }

      return {
        data: parsed?.data ?? null,
        error: parsed?.error ?? null,
      };
    } catch (err: any) {
      return {
        data: null,
        error: {
          message: err?.message || 'Unable to reach ERP backend API.',
          code: 'NETWORK_ERROR',
        },
      };
    }
  }

  then<TResult1 = DbResult<T>, TResult2 = never>(
    onfulfilled?: ((value: DbResult<T>) => TResult1 | PromiseLike<TResult1>) | null,
    onrejected?: ((reason: any) => TResult2 | PromiseLike<TResult2>) | null
  ): Promise<TResult1 | TResult2> {
    if (!this.execPromise) {
      this.execPromise = this.execute();
    }
    return this.execPromise.then(onfulfilled, onrejected);
  }
}

export const backendDb = {
  from<T = any>(table: string): BackendDbQueryBuilder<T> {
    return new BackendDbQueryBuilder<T>(table);
  },
};

export interface ErpRealtimeEvent {
  table: string;
  eventType: 'INSERT' | 'UPDATE' | 'DELETE';
  newRow?: Record<string, any> | null;
  oldRow?: Record<string, any> | null;
  timestamp: string;
}

export function subscribeErpEvents(onEvent: (evt: ErpRealtimeEvent) => void): () => void {
  if (typeof window === 'undefined' || typeof EventSource === 'undefined') {
    return () => {};
  }

  let closed = false;
  let source: EventSource | null = null;

  try {
    source = new EventSource('/api/erp/events', { withCredentials: true });
    source.addEventListener('db-change', (msg: MessageEvent) => {
      if (closed || !msg.data) return;
      try {
        const parsed = JSON.parse(msg.data) as ErpRealtimeEvent;
        if (parsed && parsed.table) {
          onEvent(parsed);
        }
      } catch {
        // Ignore malformed SSE payload
      }
    });
    source.addEventListener('system-branding', (msg: MessageEvent) => {
      if (closed || !msg.data) return;
      try {
        const parsed = JSON.parse(msg.data);
        if (parsed && typeof parsed.softwareName === 'string') {
          window.dispatchEvent(
            new CustomEvent('ensec-system-branding-updated', {
              detail: parsed,
            })
          );
        }
      } catch {
        // Ignore malformed SSE branding payload
      }
    });
  } catch {
    // Graceful fallback if SSE fails to initialize
  }

  return () => {
    closed = true;
    if (source) {
      source.close();
      source = null;
    }
  };
}
