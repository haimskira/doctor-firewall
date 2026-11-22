import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { Me } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import { FmcLogPage } from './FmcLogPage';
import type { FmcEvent } from './FmcLogPage';

const ME: Me = {
  id: 1, username: 'a', display_name: 'A', auth_provider: 'local', roles: ['admin'], permissions: ['audit:read'],
  language: 'en', theme: 'system', must_change_password: false, csrf_token: 'c',
};
const OP = 'a'.repeat(32);
const base: FmcEvent = {
  id: 1, at: '2026-11-22T10:00:00Z', op_id: OP, operation: 'collect', connection_id: 1, connection_name: 'FMC-PROD',
  snapshot_id: 12, batch_id: null, run_id: 3, step: '', kind: 'started', outcome: 'ok', method: '', path: '',
  status: null, duration_ms: null, error_code: '', detail: '', response: '',
};
const FINISHED: FmcEvent = { ...base, id: 9, kind: 'finished', outcome: 'error', duration_ms: 64000, detail: '812 requests, 1 failed' };
const EVENTS: FmcEvent[] = [
  FINISHED,
  { ...base, id: 8, kind: 'failed', outcome: 'error', step: 'access policy ACP-PROD: accessrules', error_code: 'unexpected_response', detail: 'GET /api/x/accessrules returned HTTP 500' },
  {
    ...base, id: 7, kind: 'request', outcome: 'error', step: 'access policy ACP-PROD: accessrules', method: 'GET',
    path: '/api/x/accessrules?offset=1000&limit=1000&expanded=true', status: 500, duration_ms: 1200,
    response: '{"error":{"messages":[{"description":"Unexpected internal error"}]}}',
  },
  { ...base, id: 2, kind: 'request', method: 'POST', path: '/api/fmc_platform/v1/auth/generatetoken', status: 204, duration_ms: 300 },
  base,
];

function at(path: string) {
  const calls = mockFetch((req) => {
    if (req.url === '/api/auth/me') return { status: 200, body: ME };
    if (req.url.startsWith('/api/fmc/events?') && req.url.includes('kind=finished')) {
      return { status: 200, body: { total: 1, offset: 0, rows: [FINISHED] } };
    }
    if (req.url.startsWith(`/api/fmc/events?op=${OP}`)) return { status: 200, body: { total: 5, offset: 0, rows: EVENTS } };
    return { status: 404 };
  });
  render(
    <I18nProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route path="/fmc-log" element={<FmcLogPage />} />
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </I18nProvider>,
  );
  return calls;
}

describe('FmcLogPage', () => {
  it('lists the operations with their outcome and filters a snapshot', async () => {
    const calls = at('/fmc-log?snapshot_id=12');
    expect(await screen.findByRole('cell', { name: 'Collection' })).toBeInTheDocument();
    expect(screen.getByText('failed')).toBeInTheDocument();
    expect(screen.getByText('812 requests, 1 failed')).toBeInTheDocument();
    expect(calls.some((c) => c.url.includes('snapshot_id=12') && c.url.includes('kind=finished'))).toBe(true);
    expect(screen.getByRole('link', { name: 'Export CSV' })).toHaveAttribute(
      'href',
      '/api/fmc/events/export?snapshot_id=12',
    );
  });

  it('shows where an operation failed and what the FMC answered', async () => {
    at(`/fmc-log?op=${OP}`);
    expect(await screen.findByText('Failed at: access policy ACP-PROD: accessrules')).toBeInTheDocument();
    const row = screen.getByText(/accessrules\?offset=1000/).closest('tr');
    expect(row).not.toBeNull();
    fireEvent.click(row as HTMLElement);
    expect(await screen.findByText(/Unexpected internal error/)).toBeInTheDocument();
    expect(within(screen.getByRole('table')).getByText(/generatetoken/)).toBeInTheDocument();
  });
});
