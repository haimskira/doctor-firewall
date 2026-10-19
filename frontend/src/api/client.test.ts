import { describe, expect, it, vi } from 'vitest';

import { mockFetch } from '../test/fetchMock';
import { ApiError, api, errorCode, setCsrfToken } from './client';

describe('api client', () => {
  it('sends the CSRF token only on state-changing requests', async () => {
    const calls = mockFetch(() => ({ status: 200, body: { ok: true } }));
    setCsrfToken('tok-123');
    await api('/api/x');
    await api('/api/x', 'POST', { a: 1 });
    expect(calls[0]?.headers['X-CSRF-Token']).toBeUndefined();
    expect(calls[1]?.headers['X-CSRF-Token']).toBe('tok-123');
    expect(calls[1]?.headers['Content-Type']).toBe('application/json');
    expect(calls[1]?.body).toEqual({ a: 1 });
    setCsrfToken(null);
  });

  it('uses same-origin credentials and no caching', async () => {
    mockFetch(() => ({ status: 200, body: {} }));
    await api('/api/x');
    const fetchMock = vi.mocked(fetch);
    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.credentials).toBe('same-origin');
    expect(init?.cache).toBe('no-store');
    expect(init?.redirect).toBe('error');
  });

  it('refuses anything but same-origin /api paths', async () => {
    mockFetch(() => ({ status: 200 }));
    await expect(api('https://evil.example/api/x')).rejects.toThrow('same-origin');
    await expect(api('//evil.example/api/x')).rejects.toThrow('same-origin');
  });

  it('maps error bodies to codes', async () => {
    mockFetch(() => ({ status: 403, body: { detail: 'forbidden', request_id: 'r' } }));
    const err: unknown = await api('/api/x').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(errorCode(err)).toBe('forbidden');
    expect(err instanceof ApiError ? err.status : 0).toBe(403);
  });

  it('handles 204 and non-API errors', async () => {
    mockFetch(() => ({ status: 204 }));
    await expect(api('/api/x', 'DELETE')).resolves.toBeUndefined();
    expect(errorCode(new Error('x'))).toBe('network_error');
  });
});
