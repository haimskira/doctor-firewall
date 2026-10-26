import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { InspectionCatalog, Me, Permission, RecommendationPreview, User } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { RecommendationPreviewView } from '../components/recommendations';
import { relationElements } from '../components/RelationsMap';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import { InspectionPage } from './InspectionPage';
import { UsersPage } from './UsersPage';

function me(permissions: Permission[]): Me {
  return {
    id: 1, username: 'adm', display_name: 'Adm', roles: ['admin'], permissions, language: 'en',
    auth_provider: 'local', must_change_password: false, theme: 'system', csrf_token: 'csrf-6',
  };
}

const CATALOG: InspectionCatalog = {
  profiles: [
    { tier: 'GOLD', ips_policy: 'Maximum Detection', file_policy: null, configured: false, min_level: 4, file_required: true },
    { tier: 'SILVER', ips_policy: 'IPS-OLD', file_policy: 'Block Malware', configured: true, min_level: 2, file_required: true },
    { tier: 'BRONZE', ips_policy: 'Balanced Security and Connectivity', file_policy: null, configured: false, min_level: 2, file_required: false },
  ],
  intrusion_policies: [
    { name: 'Balanced Security and Connectivity', level: 2 },
    { name: 'Maximum Detection', level: 4 },
  ],
  file_policies: [{ name: 'Block Malware', level: null }],
  snapshot_id: 7,
};

function renderPage(permissions: Permission[]) {
  const calls = mockFetch((req) => {
    if (req.url === '/api/auth/me') return { status: 200, body: me(permissions) };
    if (req.url === '/api/inspection-profiles') return { status: 200, body: CATALOG };
    if (req.url.startsWith('/api/inspection-profiles/')) return { status: 204 };
    return { status: 404, body: { detail: 'not_found' } };
  });
  render(
    <I18nProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={['/inspection']}>
          <Routes>
            <Route path="/inspection" element={<InspectionPage />} />
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </I18nProvider>,
  );
  return calls;
}

describe('InspectionPage', () => {
  it('maps tiers to FMC policies, flags missing ones, saves and resets', async () => {
    const calls = renderPage(['policy:read', 'conventions:manage']);
    const gold = await screen.findByLabelText('Intrusion policy — GOLD');
    expect(gold).toHaveValue('Maximum Detection');
    expect(within(gold).getByRole('option', { name: 'Maximum Detection · level 4' })).toBeInTheDocument();
    // A configured policy the latest snapshot does not have stays visible, flagged.
    expect(screen.getByLabelText('Intrusion policy — SILVER')).toHaveValue('IPS-OLD');
    expect(screen.getByRole('option', { name: 'IPS-OLD (Not in the latest snapshot)' })).toBeInTheDocument();

    const user = userEvent.setup();
    await user.selectOptions(screen.getByLabelText('File policy — GOLD'), 'Block Malware');
    const goldRow = gold.closest('tr');
    expect(goldRow).not.toBeNull();
    if (goldRow === null) return;
    await user.click(within(goldRow).getByRole('button', { name: 'Save' }));
    expect(calls.find((c) => c.url === '/api/inspection-profiles/GOLD')?.body).toEqual({
      ips_policy: 'Maximum Detection',
      file_policy: 'Block Malware',
    });
    expect(await screen.findByText(/Re-analyse a snapshot/)).toBeInTheDocument();

    // Only configured tiers can go back to the doctrine default.
    expect(within(goldRow).queryByRole('button', { name: 'Back to default' })).not.toBeInTheDocument();
    const silverRow = screen.getByLabelText('Intrusion policy — SILVER').closest('tr');
    if (silverRow === null) return;
    await user.click(within(silverRow).getByRole('button', { name: 'Back to default' }));
    expect(calls.some((c) => c.url === '/api/inspection-profiles/SILVER' && c.method === 'DELETE')).toBe(true);
  });

  it('is read-only without the conventions permission', async () => {
    renderPage(['policy:read']);
    expect(await screen.findByText('IPS-OLD')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
  });
});

describe('inspection preview', () => {
  it('shows the action change and the attached policies inline', async () => {
    mockFetch((req) => (req.url === '/api/auth/me' ? { status: 200, body: me(['policy:read']) } : { status: 404 }));
    const base = { id: 'r1', index: 12, name: 'APP_TO_GOLD', enabled: true, section: 'Mandatory', category: '' };
    const rule = {
      ...base, action: 'ALLOW',
      fields: { dst_net: ['GRP_SRV_GOLD'], ips_policy: ['Maximum Detection'] },
      status: 'modified' as const,
      changes: { action: { added: ['ALLOW'], removed: ['TRUST'] }, ips_policy: { added: ['Maximum Detection'], removed: [] } },
    };
    const preview: RecommendationPreview = {
      before: [{ ...base, action: 'TRUST', fields: { dst_net: ['GRP_SRV_GOLD'] } }],
      after: [rule],
      rules: [{ policy: 'ACP-DC', index: 7, name: 'WEB_TO_GOLD', id: 'r7' }],
    };
    render(
      <I18nProvider>
        <AuthProvider>
          <MemoryRouter>
            <RecommendationPreviewView preview={preview} view="inline" snapshotId={7} />
          </MemoryRouter>
        </AuthProvider>
      </I18nProvider>,
    );
    expect(await screen.findByText('Reached over TLS by')).toBeInTheDocument();
    expect(screen.getByText('TRUST').closest('del')).not.toBeNull();
    expect(screen.getByText('Intrusion policy')).toBeInTheDocument();
    expect(screen.getByText('Maximum Detection').closest('ins')).not.toBeNull();
    expect(screen.getByText('Reached over TLS by')).toBeInTheDocument();
    expect(screen.getByText('WEB_TO_GOLD')).toBeInTheDocument();
  });
});

describe('UsersPage with directory sign-in', () => {
  it('creates an LDAP account without a password and hides password reset for it', async () => {
    const users: User[] = [
      {
        id: 2, username: 'dana', display_name: 'Dana', auth_provider: 'ldap', roles: ['optimizer'], is_active: true,
        must_change_password: false, language: 'he', created_at: '2026-10-21T10:00:00Z', last_login_at: null,
      },
    ];
    const calls = mockFetch((req) => {
      if (req.url === '/api/auth/me') return { status: 200, body: me(['policy:read', 'users:manage']) };
      if (req.url === '/api/users' && req.method === 'GET') return { status: 200, body: users };
      if (req.url === '/api/users' && req.method === 'POST') return { status: 201, body: users[0] };
      return { status: 404, body: { detail: 'not_found' } };
    });
    render(
      <I18nProvider>
        <AuthProvider>
          <MemoryRouter>
            <UsersPage />
          </MemoryRouter>
        </AuthProvider>
      </I18nProvider>,
    );
    const row = (await screen.findByText('dana')).closest('tr');
    if (row === null) throw new Error('row');
    expect(within(row).getByText('LDAP / AD')).toBeInTheDocument();
    expect(within(row).queryByRole('button', { name: 'Reset password' })).not.toBeInTheDocument();

    const user = userEvent.setup();
    expect(screen.getByLabelText('Temporary password')).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText('Sign-in'), 'tacacs');
    expect(screen.queryByLabelText('Temporary password')).not.toBeInTheDocument();
    await user.type(screen.getByLabelText('Username'), 'erez');
    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(calls.find((c) => c.url === '/api/users' && c.method === 'POST')?.body).toEqual({
      username: 'erez', display_name: '', roles: ['viewer'], auth_provider: 'tacacs',
    });
  });
});

describe('relations map layout', () => {
  it('puts members, the object, its group chain and the rules in columns and marks redundant links', () => {
    const rel = {
      object: { id: 'x', name: 'H_X', kind: 'host', value: '10.0.0.7' },
      nodes: [
        { id: 'x', kind: 'host', label: 'H_X', role: 'self' as const, depth: 0, detail: '' },
        { id: 'g1', kind: 'network_group', label: 'G1', role: 'ancestor' as const, depth: 1, detail: '' },
        { id: 'g2', kind: 'network_group', label: 'G2', role: 'ancestor' as const, depth: 2, detail: '' },
        { id: 'rule:r1', kind: 'rule', label: '#4 R1', role: 'rule' as const, depth: 3, detail: 'ACP' },
        { id: 'n', kind: 'network', label: 'NET', role: 'overlap' as const, depth: 0, detail: '10.0.0.0/24' },
      ],
      edges: [
        { source: 'x', target: 'g1', kind: 'member' as const, label: '' },
        { source: 'g1', target: 'g2', kind: 'member' as const, label: '' },
        { source: 'g2', target: 'rule:r1', kind: 'uses' as const, label: 'dst_net' },
        { source: 'x', target: 'rule:r1', kind: 'uses' as const, label: 'dst_net' },
        { source: 'x', target: 'n', kind: 'overlap' as const, label: 'within' },
      ],
      issues: [
        { kind: 'redundant_reference' as const, where_id: 'r1', where_name: '#4 R1', removed: 'H_X', kept: 'G2', recommendation_id: 9 },
      ],
      truncated: false,
    };
    const els = relationElements(rel, false);
    const x = (id: string) => els.find((e) => e.data.id === id)?.position?.x ?? NaN;
    expect(x('x')).toBe(0);
    expect(x('g1') < x('g2') && x('g2') < x('rule:r1')).toBe(true);
    expect(els.find((e) => e.data.id === 'n')?.classes).toContain('rel-overlap');
    const redundant = els.filter((e) => typeof e.classes === 'string' && e.classes.includes('redundant'));
    expect(redundant.map((e) => `${String(e.data.source)}->${String(e.data.target)}`)).toEqual(['x->rule:r1']);
    expect(relationElements(rel, true).find((e) => e.data.id === 'g2')?.position?.x).toBe(-x('g2'));
  });
});
