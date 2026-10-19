import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { Me, RuleRow, Snapshot } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import type { Recorded } from '../test/fetchMock';
import { FindingsPage } from './FindingsPage';
import { ObjectDetailPage } from './ObjectDetailPage';
import { RulebasePage } from './RulebasePage';
import { SnapshotsPage } from './SnapshotsPage';

const ME: Me = {
  id: 1,
  username: 'opt',
  display_name: 'Opt',
  roles: ['optimizer'],
  permissions: ['policy:read', 'collect:run', 'changeset:write'],
  language: 'en',
  must_change_password: false,
  csrf_token: 'csrf-1',
};

const SNAP: Snapshot = {
  id: 7,
  connection_id: 1,
  connection_name: 'FMC-HA',
  status: 'complete',
  requested_by: 'opt',
  created_at: '2026-10-19T10:00:00Z',
  started_at: '2026-10-19T10:00:00Z',
  finished_at: '2026-10-19T10:01:00Z',
  analyzed_at: '2026-10-19T10:02:00Z',
  fmc_version: '10.1.0 (build 117)',
  error: null,
  error_detail: null,
  stats: { rules: 3, objects: 10, clusters: 1 },
};

function rule(index: number, extra: Partial<RuleRow> = {}): RuleRow {
  return {
    id: `r${String(index)}`,
    index,
    section: 'Mandatory',
    category: 'DC-Inbound',
    name: `RULE-${String(index)}`,
    enabled: true,
    action: 'ALLOW',
    hit_count: 5,
    last_hit: null,
    ips_policy: null,
    file_policy: null,
    log_begin: false,
    log_end: true,
    refs: {},
    ...extra,
  };
}

type Handler = (req: Recorded) => { status: number; body?: unknown } | undefined;

function setup(path: string, routes: ReactNode, handler: Handler): Recorded[] {
  const calls = mockFetch((req) => {
    if (req.url === '/api/auth/me') return { status: 200, body: ME };
    if (req.url.startsWith('/api/snapshots?')) return { status: 200, body: [SNAP] };
    return handler(req) ?? { status: 404, body: { detail: 'not_found' } };
  });
  render(
    <I18nProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <Routes>{routes}</Routes>
        </MemoryRouter>
      </AuthProvider>
    </I18nProvider>,
  );
  return calls;
}

describe('RulebasePage', () => {
  beforeEach(() => {
    // jsdom has no layout: give elements a viewport-sized box so the virtualizer renders rows.
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue(
      DOMRect.fromRect({ x: 0, y: 0, width: 1200, height: 800 }),
    );
    vi.spyOn(HTMLElement.prototype, 'offsetHeight', 'get').mockReturnValue(800);
    vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockReturnValue(1200);
  });

  it('shows rules in FMC order with category bands, object links and flagged literals', async () => {
    const rules = [
      rule(1, {
        refs: {
          src_net: [{ id: 'g1', name: 'GRP_SRC_FIN', kind: 'network_group', literal: null }],
          dst_net: [{ id: null, name: '', kind: null, literal: '1.1.1.1/32' }],
          dst_port: [{ id: 'p1', name: 'SVC_TCP1433', kind: 'port', literal: null }],
        },
      }),
      rule(2, { enabled: false }),
      rule(3, { section: 'Default', category: '--Undefined--', name: 'ANY_ANY', hit_count: 0 }),
    ];
    const calls = setup('/rules', <Route path="/rules" element={<RulebasePage />} />, (req) => {
      if (req.url === '/api/snapshots/7/clusters') {
        return {
          status: 200,
          body: [{ fmc_id: 'c1', name: 'FTD-CL01', kind: 'ha_pair', sw_version: '7.7.13', model: 'x', members: [], policy_fmc_id: 'p1', policy_name: 'ACP-1', rule_count: 3 }],
        };
      }
      if (req.url.startsWith('/api/snapshots/7/policies/p1/rules')) {
        return { status: 200, body: { policy_fmc_id: 'p1', policy_name: 'ACP-1', categories: [], total: 3, offset: 0, rows: rules } };
      }
      return undefined;
    });
    expect(await screen.findByText('RULE-1')).toBeInTheDocument();
    expect(screen.getByText('ANY_ANY')).toBeInTheDocument();
    expect(screen.getByText('3 rules', { exact: false })).toBeInTheDocument();
    expect(screen.getByText('DC-Inbound')).toBeInTheDocument();
    expect(screen.getByText('--Undefined--')).toBeInTheDocument();
    const link = screen.getByRole('link', { name: 'GRP_SRC_FIN' });
    expect(link).toHaveAttribute('href', '/objects/g1?snapshot=7');
    expect(screen.getByText('1.1.1.1/32').closest('.literal')).toHaveAttribute('title', 'Inline value without an object');
    expect(screen.getByText('disabled')).toBeInTheDocument();
    expect(screen.getAllByText('any').length).toBeGreaterThan(0);
    const ruleCall = calls.find((c) => c.url.includes('/rules?'));
    expect(ruleCall?.url).toContain('offset=0');
  });

  it('sends the search to the server (debounced)', async () => {
    const calls = setup('/rules', <Route path="/rules" element={<RulebasePage />} />, (req) => {
      if (req.url === '/api/snapshots/7/clusters') {
        return { status: 200, body: [{ fmc_id: 'c1', name: 'C', kind: 'ha_pair', sw_version: '', model: '', members: [], policy_fmc_id: 'p1', policy_name: 'ACP', rule_count: 1 }] };
      }
      if (req.url.includes('/rules?')) {
        return { status: 200, body: { policy_fmc_id: 'p1', policy_name: 'ACP', categories: [], total: 1, offset: 0, rows: [rule(1)] } };
      }
      return undefined;
    });
    const box = await screen.findByPlaceholderText('Rule name, object or value');
    await userEvent.type(box, 'gold & db');
    await waitFor(() => {
      expect(calls.some((c) => c.url.includes('q=gold%20%26%20db'))).toBe(true);
    });
  });
});

describe('ObjectDetailPage', () => {
  it('shows members, the membership tree and where-used through groups', async () => {
    setup('/objects/h1?snapshot=7', <Route path="/objects/:objectId" element={<ObjectDetailPage />} />, (req) => {
      if (req.url === '/api/snapshots/7/objects/h1') {
        return {
          status: 200,
          body: {
            object: { id: 'h1', name: 'H_GOLD_DB1', kind: 'host', fmc_type: 'Host', value: '10.20.5.11/32', stub: false, rule_refs: 0, member_of: 2 },
            attrs: {},
            members: [],
            member_of: [
              { group_id: 'g1', group_name: 'GRP_SRV_GOLD', child_id: 'h1', depth: 1 },
              { group_id: 'g2', group_name: 'GRP_DC_ALL', child_id: 'g1', depth: 2 },
            ],
            used_by: [
              { policy_fmc_id: 'p', rule_id: 'r9', rule_index: 9, rule_name: 'FIN_TO_GOLD', field: 'dst_net', via_id: 'g1', via_name: 'GRP_SRV_GOLD' },
            ],
            used_by_total: 1,
          },
        };
      }
      return undefined;
    });
    expect(await screen.findByText('H_GOLD_DB1')).toBeInTheDocument();
    expect(screen.getByText('10.20.5.11/32')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'GRP_DC_ALL' })).toHaveAttribute('href', '/objects/g2?snapshot=7');
    const table = screen.getByRole('table');
    expect(within(table).getByText('FIN_TO_GOLD')).toBeInTheDocument();
    expect(within(table).getByText('destination')).toBeInTheDocument();
    expect(within(table).getByText('GRP_SRV_GOLD')).toBeInTheDocument();
  });
});

describe('SnapshotsPage', () => {
  it('starts a pull with the CSRF token and offers resume on failures', async () => {
    const failed: Snapshot = { ...SNAP, id: 8, status: 'failed', error: 'config_changed', stats: {} };
    const calls = mockFetch((req) => {
      if (req.url === '/api/auth/me') return { status: 200, body: ME };
      if (req.url === '/api/connections') return { status: 200, body: [{ id: 1, name: 'FMC-HA', sync_interval_minutes: null }] };
      if (req.url.startsWith('/api/snapshots?')) return { status: 200, body: [failed, SNAP] };
      if (req.method === 'POST') return { status: 202, body: { ...SNAP, status: 'pending' } };
      return { status: 404, body: { detail: 'not_found' } };
    });
    render(
      <I18nProvider>
        <AuthProvider>
          <MemoryRouter>
            <SnapshotsPage />
          </MemoryRouter>
        </AuthProvider>
      </I18nProvider>,
    );
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Pull now: FMC-HA' }));
    const post = calls.find((c) => c.url === '/api/fmc/connections/1/collect');
    expect(post?.method).toBe('POST');
    expect(post?.headers['X-CSRF-Token']).toBe('csrf-1');
    expect(await screen.findByText('Collection queued.')).toBeInTheDocument();
    expect(screen.getByText(/configuration changed during the pull/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Resume' }));
    expect(calls.some((c) => c.url === '/api/snapshots/8/resume' && c.method === 'POST')).toBe(true);
    expect(screen.getByText('3 rules · 10 objects · 1 clusters')).toBeInTheDocument();
  });
});

describe('FindingsPage', () => {
  it('summarises by kind and filters on the server', async () => {
    const calls = setup('/findings', <Route path="/findings" element={<FindingsPage />} />, (req) => {
      if (req.url.startsWith('/api/snapshots/7/findings')) {
        return {
          status: 200,
          body: {
            total: 1,
            offset: 0,
            summary: { group_cycle: { high: 1 }, unused_object: { info: 4 } },
            rows: [{ id: 1, kind: 'group_cycle', severity: 'high', policy_fmc_id: null, title: 'Group cycle: A -> B', details: { groups: ['A', 'B'] } }],
          },
        };
      }
      return undefined;
    });
    expect(await screen.findByText('Group cycle: A -> B')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Unused objects (4)' })).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Group cycles (1)' }));
    await waitFor(() => {
      expect(calls.some((c) => c.url.includes('kind=group_cycle'))).toBe(true);
    });
    await user.click(screen.getByText('Group cycle: A -> B'));
    expect(screen.getByText(/"groups"/)).toBeInTheDocument();
  });
});
