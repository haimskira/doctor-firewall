/**
 * Same-origin JSON client for /api.
 *
 * - The session lives in an HttpOnly cookie the browser sends automatically;
 *   JavaScript never sees it.
 * - The CSRF token is kept in memory only (never in web storage) and attached to
 *   every state-changing request.
 * - Error responses are reduced to a machine-readable code the UI translates.
 */

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  /** Parsed error body (e.g. per-line CSV errors); never contains submitted values. */
  readonly body: unknown;

  constructor(status: number, code: string, body: unknown = null) {
    super(`API error ${String(status)}: ${code}`);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

export async function api<T>(path: string, method: Method = 'GET', body?: unknown): Promise<T> {
  if (!path.startsWith('/api/')) {
    throw new Error('api() only talks to same-origin /api paths');
  }
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  if (method !== 'GET' && csrfToken !== null) {
    headers['X-CSRF-Token'] = csrfToken;
  }
  const init: RequestInit = {
    method,
    headers,
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
  };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  const response = await fetch(path, init);
  if (response.status === 204) {
    return undefined as T;
  }
  let data: unknown;
  try {
    data = await response.json();
  } catch {
    data = null;
  }
  if (!response.ok) {
    const code = isRecord(data) && typeof data['detail'] === 'string' ? data['detail'] : 'http_error';
    throw new ApiError(response.status, code, data);
  }
  return data as T;
}

export function errorCode(error: unknown): string {
  return error instanceof ApiError ? error.code : 'network_error';
}
