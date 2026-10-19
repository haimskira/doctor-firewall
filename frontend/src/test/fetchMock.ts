import { vi } from 'vitest';

export interface Recorded {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

type Handler = (req: Recorded) => { status: number; body?: unknown };

/** Install a fetch stub that routes requests to `handler` and records them. */
export function mockFetch(handler: Handler): Recorded[] {
  const calls: Recorded[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn((input: string, init: RequestInit = {}) => {
      const headers = (init.headers ?? {}) as Record<string, string>;
      const req: Recorded = {
        url: input,
        method: init.method ?? 'GET',
        headers,
        body: typeof init.body === 'string' ? (JSON.parse(init.body) as unknown) : undefined,
      };
      calls.push(req);
      const { status, body } = handler(req);
      return Promise.resolve(
        new Response(status === 204 ? null : JSON.stringify(body ?? {}), {
          status,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }),
  );
  return calls;
}
