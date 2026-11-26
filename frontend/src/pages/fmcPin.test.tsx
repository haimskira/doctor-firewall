import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { FmcCertificate, Me } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import { FmcPage } from './FmcPage';

const ME: Me = {
  id: 1, username: 'admin', display_name: 'admin', roles: ['admin'], permissions: ['fmc:manage'], language: 'en',
  auth_provider: 'local', must_change_password: false, theme: 'system', csrf_token: 'csrf',
};

const CERT: FmcCertificate = {
  pem: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n',
  sha256: 'AA:BB:CC',
  subject: 'CN=firepower',
  issuer: 'CN=firepower',
  not_before: '2026-01-01T00:00:00Z',
  not_after: '2036-01-01T00:00:00Z',
  self_signed: true,
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe('FmcPage certificate pinning', () => {
  it('fetches the certificate, requires confirmation and sends the pin', async () => {
    const calls = mockFetch((req) => {
      if (req.url === '/api/auth/me') return { status: 200, body: ME };
      if (req.url === '/api/fmc/connections' && req.method === 'GET') return { status: 200, body: [] };
      if (req.url === '/api/fmc/connections/certificate') return { status: 200, body: CERT };
      if (req.url === '/api/fmc/connections' && req.method === 'POST') return { status: 201, body: {} };
      return { status: 404, body: { detail: 'not_found' } };
    });
    render(
      <I18nProvider>
        <AuthProvider>
          <MemoryRouter>
            <FmcPage />
          </MemoryRouter>
        </AuthProvider>
      </I18nProvider>,
    );
    const [name, host, , user] = await screen.findAllByRole('textbox');
    if (name === undefined || host === undefined || user === undefined) throw new Error('form');
    await userEvent.type(name, 'FMC');
    await userEvent.type(host, '10.0.0.5');
    await userEvent.type(user, 'api');
    await userEvent.type(screen.getByLabelText('API password'), 'pw');

    await userEvent.click(screen.getByRole('button', { name: 'Fetch certificate' }));
    expect(await screen.findByText('AA:BB:CC')).toBeInTheDocument();
    expect(calls.find((c) => c.url === '/api/fmc/connections/certificate')?.body).toEqual({
      host: '10.0.0.5',
      port: 443,
    });
    // Not confirmed yet: saving is blocked.
    const save = screen.getByRole('button', { name: 'Save' });
    expect(save).toBeDisabled();
    await userEvent.click(screen.getByRole('checkbox', { name: /I verified this fingerprint/ }));
    expect(save).toBeEnabled();
    await userEvent.click(save);
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'POST' && c.url === '/api/fmc/connections')).toBe(true);
    });
    const body = calls.find((c) => c.method === 'POST' && c.url === '/api/fmc/connections')
      ?.body as Record<string, unknown>;
    expect(body['pinned_cert']).toBe(CERT.pem);
    expect(body['host']).toBe('10.0.0.5');
  });
});
