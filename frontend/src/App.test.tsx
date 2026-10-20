import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { App } from './App';
import type { Me, Permission, Role } from './api/types';
import { AuthProvider } from './auth/AuthProvider';
import { Ltr } from './components/common';
import { I18nProvider } from './i18n/I18nProvider';
import { mockFetch } from './test/fetchMock';

const ADMIN_PERMS: Permission[] = ['policy:read', 'audit:read', 'users:manage', 'fmc:manage'];

function me(roles: Role[], permissions: Permission[], extra: Partial<Me> = {}): Me {
  return {
    id: 1,
    username: 'alice',
    display_name: 'Alice',
    roles,
    permissions,
    language: 'en',
    must_change_password: false,
    csrf_token: 'csrf-abc',
    ...extra,
  };
}

function renderApp(path = '/') {
  return render(
    <I18nProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <App />
        </MemoryRouter>
      </AuthProvider>
    </I18nProvider>,
  );
}

const NO_SESSION = { status: 401, body: { detail: 'not_authenticated' } };
/** The shell asks for snapshots (alerts badge); an empty estate answers with none. */
const NO_SNAPSHOTS = (url: string) => (url.startsWith('/api/snapshots') ? { status: 200, body: [] } : undefined);

describe('App', () => {
  it('shows the login page without a session, then signs in', async () => {
    let loggedIn = false;
    const calls = mockFetch((req) => {
      if (req.url === '/api/auth/login') {
        loggedIn = true;
        return { status: 200, body: me(['viewer'], ['policy:read']) };
      }
      if (req.url === '/api/auth/me' && loggedIn) {
        return { status: 200, body: me(['viewer'], ['policy:read']) };
      }
      return NO_SESSION;
    });
    renderApp();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText('שם משתמש'), 'alice');
    await user.type(screen.getByLabelText('סיסמה'), 'Secret-Pass-123');
    await user.click(screen.getByRole('button', { name: 'כניסה' }));
    expect(await screen.findByRole('heading', { name: 'Summary Dashboard' })).toBeInTheDocument();
    const login = calls.find((c) => c.url === '/api/auth/login');
    expect(login?.body).toEqual({ username: 'alice', password: 'Secret-Pass-123' });
    // The stored per-user language (en) is applied after login.
    expect(document.documentElement.dir).toBe('ltr');
  });

  it('shows a translated error on bad credentials and clears the password', async () => {
    mockFetch((req) =>
      req.url === '/api/auth/login'
        ? { status: 401, body: { detail: 'invalid_credentials' } }
        : NO_SESSION,
    );
    renderApp();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText('שם משתמש'), 'alice');
    await user.type(screen.getByLabelText('סיסמה'), 'nope');
    await user.click(screen.getByRole('button', { name: 'כניסה' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('שם משתמש או סיסמה שגויים.');
    expect(screen.getByLabelText('סיסמה')).toHaveValue('');
  });

  it('hides admin navigation from a viewer', async () => {
    mockFetch((req) => NO_SNAPSHOTS(req.url) ?? { status: 200, body: me(['viewer'], ['policy:read']) });
    renderApp();
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Administration' }));
    expect(screen.getByRole('menuitem', { name: 'Settings' })).toBeInTheDocument();
    expect(screen.queryByRole('menuitem', { name: 'Users' })).not.toBeInTheDocument();
    // Without the audit log, Events & Logs has a single entry: a direct link, no flyout.
    expect(screen.getByRole('link', { name: 'Events & Logs' })).toHaveAttribute('href', '/findings');
    expect(screen.queryByRole('menuitem', { name: 'Audit log' })).not.toBeInTheDocument();
  });

  it('redirects a viewer away from admin pages', async () => {
    mockFetch((req) => NO_SNAPSHOTS(req.url) ?? { status: 200, body: me(['viewer'], ['policy:read']) });
    renderApp('/users');
    expect(await screen.findByRole('heading', { name: 'Summary Dashboard' })).toBeInTheDocument();
  });

  it('shows admin navigation to an administrator', async () => {
    mockFetch(
      (req) =>
        NO_SNAPSHOTS(req.url) ??
        (req.url === '/api/fmc/connections' ? { status: 200, body: [] } : { status: 200, body: me(['admin'], ADMIN_PERMS) }),
    );
    renderApp('/?tab=status');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Administration' }));
    expect(screen.getByRole('menuitem', { name: 'Users' })).toHaveAttribute('href', '/users');
    await user.click(screen.getByRole('button', { name: 'Integrations' }));
    expect(screen.getByRole('menuitem', { name: 'FMC connection' })).toHaveAttribute('href', '/fmc');
    expect(screen.queryByRole('menuitem', { name: 'Users' })).not.toBeInTheDocument(); // one flyout at a time
    expect(await screen.findByText('No FMC connection is configured yet.')).toBeInTheDocument();
  });

  it('forces a password change before anything else', async () => {
    const calls = mockFetch((req) => {
      if (req.url === '/api/auth/change-password') {
        return { status: 200, body: me(['admin'], ADMIN_PERMS) };
      }
      if (req.url === '/api/users') {
        return { status: 200, body: [] };
      }
      const empty = NO_SNAPSHOTS(req.url);
      if (empty !== undefined) return empty;
      return { status: 200, body: me(['admin'], ADMIN_PERMS, { must_change_password: true }) };
    });
    renderApp('/users');
    expect(
      await screen.findByText('You must set a new password before continuing.'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Administration' })).not.toBeInTheDocument();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText('Current password'), 'Old-Password-1');
    await user.type(screen.getByLabelText('New password'), 'short');
    await user.type(screen.getByLabelText('Confirm new password'), 'short');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Use at least 12 characters.');
    expect(calls.some((c) => c.url === '/api/auth/change-password')).toBe(false);

    await user.clear(screen.getByLabelText('New password'));
    await user.clear(screen.getByLabelText('Confirm new password'));
    await user.type(screen.getByLabelText('New password'), 'Brand-New-Pass-77');
    await user.type(screen.getByLabelText('Confirm new password'), 'Brand-New-Pass-77');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Administration' })).toBeInTheDocument();
    });
    const change = calls.find((c) => c.url === '/api/auth/change-password');
    expect(change?.headers['X-CSRF-Token']).toBe('csrf-abc');
  });

  it('shows high-severity findings on the bell and searches objects from the top bar', async () => {
    const calls = mockFetch((req) => {
      if (req.url === '/api/snapshots?limit=20') {
        return { status: 200, body: [{ id: 4, status: 'complete', analyzed_at: '2026-10-20T10:00:00Z' }] };
      }
      if (req.url === '/api/snapshots/4/findings?severity=high&limit=1') {
        return { status: 200, body: { total: 12, offset: 0, summary: {}, rows: [] } };
      }
      return NO_SNAPSHOTS(req.url) ?? { status: 200, body: me(['viewer'], ['policy:read']) };
    });
    renderApp();
    const bell = await screen.findByRole('button', { name: '12 high-severity findings' });
    expect(bell).toHaveTextContent('12');
    const user = userEvent.setup();
    await user.type(screen.getByRole('searchbox', { name: 'Search objects' }), 'H_GOLD{Enter}');
    // The search opens the object explorer filtered by the query.
    expect(await screen.findByText('Object Management', { selector: '[aria-current="page"]' })).toBeInTheDocument();
    expect(calls.some((c) => c.url === '/api/snapshots/4/findings?severity=high&limit=1')).toBe(true);
  });

  it('signs out', async () => {
    let session = true;
    mockFetch((req) => {
      if (req.url === '/api/auth/logout') {
        session = false;
        return { status: 204 };
      }
      if (!session) return NO_SESSION;
      return NO_SNAPSHOTS(req.url) ?? { status: 200, body: me(['viewer'], ['policy:read']) };
    });
    renderApp();
    const user = userEvent.setup();
    // Sign-out lives in the user menu of the top bar, as in the FMC.
    await user.click(await screen.findByRole('button', { name: 'Alice' }));
    await user.click(screen.getByRole('menuitem', { name: 'Sign out' }));
    expect(await screen.findByRole('button', { name: /Sign in|כניסה/ })).toBeInTheDocument();
  });
});

describe('Ltr', () => {
  it('isolates left-to-right content', () => {
    render(<Ltr>10.20.5.0/24</Ltr>);
    const el = screen.getByText('10.20.5.0/24');
    expect(el.tagName).toBe('BDI');
    expect(el).toHaveAttribute('dir', 'ltr');
  });
});
