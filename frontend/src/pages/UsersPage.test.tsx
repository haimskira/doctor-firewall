import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { Me, User, UserChangeRequest } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import { UsersPage } from './UsersPage';

const ME: Me = {
  id: 1, username: 'adm', display_name: 'Adm', roles: ['admin'], permissions: ['policy:read', 'users:manage'],
  language: 'en', auth_provider: 'local', must_change_password: false, theme: 'system', csrf_token: 'csrf-u',
};

const REQUESTS: UserChangeRequest[] = [
  {
    id: 7, kind: 'create', target_user_id: null, target_username: 'newapp', payload: { roles: ['approver'] },
    requested_by: 'other', requested_at: '2026-11-04T10:00:00Z', expires_at: '2026-11-05T10:00:00Z',
    status: 'pending', decided_by: null, decided_at: null,
  },
  {
    id: 8, kind: 'password_reset', target_user_id: 5, target_username: 'bob', payload: {},
    requested_by: 'adm', requested_at: '2026-11-04T10:00:00Z', expires_at: '2026-11-05T10:00:00Z',
    status: 'pending', decided_by: null, decided_at: null,
  },
];

function renderPage() {
  render(
    <I18nProvider>
      <AuthProvider>
        <MemoryRouter>
          <UsersPage />
        </MemoryRouter>
      </AuthProvider>
    </I18nProvider>,
  );
}

describe('UsersPage two-administrator requests', () => {
  it('lets only another administrator approve and shows the issued password once', async () => {
    const users: User[] = [];
    const calls = mockFetch((req) => {
      if (req.url === '/api/auth/me') return { status: 200, body: ME };
      if (req.url === '/api/users' && req.method === 'GET') return { status: 200, body: users };
      if (req.url === '/api/users/requests' && req.method === 'GET') return { status: 200, body: REQUESTS };
      if (req.url === '/api/users/requests/7/approve') {
        return { status: 200, body: { request_id: 7, status: 'approved', user: null, temporary_password: 'Tmp-Secret-1aA' } };
      }
      return { status: 404, body: { detail: 'not_found' } };
    });
    renderPage();
    const other = (await screen.findByText('newapp')).closest('tr');
    if (other === null) throw new Error('row');
    const own = screen.getByText('bob').closest('tr');
    if (own === null) throw new Error('row');
    expect(within(own).queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(within(own).getByText('Waiting for a second administrator to approve the request.')).toBeInTheDocument();

    await userEvent.setup().click(within(other).getByRole('button', { name: 'Approve' }));
    expect(await screen.findByText('Tmp-Secret-1aA')).toBeInTheDocument();
    expect(calls.some((c) => c.url === '/api/users/requests/7/approve' && c.method === 'POST')).toBe(true);
  });

  it('says it waits for a second administrator after a queued create', async () => {
    mockFetch((req) => {
      if (req.url === '/api/auth/me') return { status: 200, body: ME };
      if (req.url === '/api/users' && req.method === 'GET') return { status: 200, body: [] };
      if (req.url === '/api/users/requests' && req.method === 'GET') return { status: 200, body: [] };
      if (req.url === '/api/users' && req.method === 'POST') {
        return { status: 202, body: { request_id: 9, status: 'pending' } };
      }
      return { status: 404, body: { detail: 'not_found' } };
    });
    renderPage();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText('Username'), 'carol');
    await user.type(screen.getByLabelText('Temporary password'), 'Temp-Pass-1234');
    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(await screen.findByText('Waiting for a second administrator to approve the request.')).toBeInTheDocument();
  });
});
