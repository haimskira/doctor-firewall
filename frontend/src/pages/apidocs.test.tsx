import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { Me } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import { ApiDocsPage } from './ApiDocsPage';

const ME: Me = {
  id: 1,
  username: 'dev',
  display_name: 'Dev',
  roles: ['viewer'],
  permissions: ['policy:read'],
  language: 'en',
  auth_provider: 'local',
  must_change_password: false,
  theme: 'system',
  csrf_token: 'csrf-1',
};

const SCHEMA = {
  info: { title: 'Doctor Firewall — read API', version: '0.7' },
  paths: {
    '/api/snapshots': { get: { summary: 'List snapshots', tags: ['inventory'], parameters: [{ name: 'limit', in: 'query', schema: { type: 'integer' } }] } },
    '/api/snapshots/{snapshot_id}/findings': {
      get: {
        summary: 'Findings',
        tags: ['inventory'],
        parameters: [
          { name: 'snapshot_id', in: 'path', required: true, schema: { type: 'integer' } },
          { name: 'severity', in: 'query', schema: { anyOf: [{ enum: ['info', 'low', 'medium', 'high'] }, { type: 'null' }] } },
        ],
      },
    },
  },
};

function setup() {
  const calls = mockFetch((req) => {
    if (req.url === '/api/auth/me') return { status: 200, body: ME };
    if (req.url === '/api/tokens' && req.method === 'GET') return { status: 200, body: [] };
    if (req.url === '/api/tokens' && req.method === 'POST') {
      return { status: 201, body: { id: 3, name: 'SIEM', prefix: 'ab12cd34', owner: 'dev', created_at: '2026-10-28T10:00:00Z', expires_at: '2027-01-26T10:00:00Z', last_used_at: null, revoked_at: null, token: 'dfk_ab12cd34_secret' } };
    }
    if (req.url === '/api/openapi.json') return { status: 200, body: SCHEMA };
    if (req.url === '/api/snapshots/7/findings?severity=high') return { status: 200, body: { total: 1, rows: [{ kind: 'shadowed_rule' }] } };
    return { status: 404, body: { detail: 'not_found' } };
  });
  render(
    <I18nProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={['/api-docs']}>
          <Routes>
            <Route path="/api-docs" element={<ApiDocsPage />} />
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </I18nProvider>,
  );
  return calls;
}

describe('ApiDocsPage', () => {
  it('creates a token that is shown once, and explores and runs the read API', async () => {
    const calls = setup();
    const user = userEvent.setup();
    expect(await screen.findByText(/Tokens are read-only/)).toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: 'Tokens' }));
    await user.type(screen.getByLabelText('Name (what uses it)'), 'SIEM');
    await user.click(screen.getByRole('button', { name: 'Create token' }));
    expect(await screen.findByText('dfk_ab12cd34_secret')).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'POST' && c.url === '/api/tokens')?.body).toEqual({ name: 'SIEM', days: 90 });

    await user.click(screen.getByRole('tab', { name: 'API explorer' }));
    expect(await screen.findByText('2 read endpoints')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /snapshot_id}\/findings/ }));
    const run = screen.getByRole('button', { name: 'Try it' });
    expect(run).toBeDisabled(); // the path parameter is required
    await user.type(screen.getByLabelText('snapshot_id'), '7');
    await user.type(screen.getByLabelText('severity'), 'high');
    expect(screen.getByText(/Authorization: Bearer \$DF_TOKEN/)).toHaveTextContent('/api/snapshots/7/findings?severity=high');
    await user.click(run);
    expect(await screen.findByText(/HTTP 200 in/)).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText(/"shadowed_rule"/)).toBeInTheDocument();
    });

    await user.click(screen.getByRole('tab', { name: 'Findings & recommendations' }));
    const shadowed = screen.getByText('shadowed_rule').closest('tr');
    if (shadowed === null) throw new Error('row');
    expect(within(shadowed).getByText('Shadowed rules')).toBeInTheDocument();
    const dead = screen.getByText('remove_dead_rule').closest('tr');
    if (dead === null) throw new Error('row');
    expect(within(dead).getByText('Changes access')).toBeInTheDocument();
  });
});
