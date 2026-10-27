import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { Me, Permission, Recommendation, RecommendationDetail, RuleRow, Snapshot } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import type { Recorded } from '../test/fetchMock';
import { NamingPage } from './NamingPage';
import { RecommendationsPage } from './RecommendationsPage';
import { RulebasePage } from './RulebasePage';

function me(permissions: Permission[]): Me {
  return {
    id: 1, username: 'opt', display_name: 'Opt', roles: ['optimizer'], permissions, language: 'en',
    auth_provider: 'local', must_change_password: false, theme: 'system', csrf_token: 'csrf-3',
  };
}
const SNAP = {
  id: 7, connection_id: 1, connection_name: 'FMC', status: 'complete', requested_by: 'x',
  created_at: '2026-10-20T10:00:00Z', started_at: null, finished_at: null, analyzed_at: '2026-10-20T11:00:00Z',
  fmc_version: null, error: null, error_detail: null,
  stats: { naming: { network_group: { compliant: 4, noncompliant: 9, proposed: 6 } } },
} satisfies Snapshot;

type Handler = (req: Recorded) => { status: number; body?: unknown } | undefined;

function setup(path: string, routes: ReactNode, handler: Handler, permissions: Permission[]): Recorded[] {
  const calls = mockFetch((req) => {
    if (req.url === '/api/auth/me') return { status: 200, body: me(permissions) };
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

const SPLIT: Recommendation = {
  id: 5, kind: 'split_rule', policy_fmc_id: 'p1', title: 'Split #12 MIXED by destination tier: GOLD, SILVER',
  principle: 'one_destination_tier', priority: 70, targets: [{ type: 'rule', id: 'r12', name: 'MIXED', index: 12 }],
  display: 'split', deploy_cost: 2, ace_delta: 0, score_delta: 25, warnings: ['unclassified_part', 'brand_new_code'],
  fingerprint: 'f'.repeat(64), decision: null, executable: true, blocked: [],
};
const REMOVE: Recommendation = {
  ...SPLIT, id: 6, kind: 'remove_dead_rule', title: 'Remove #40 OLD: permit rule without hits', principle: 'rule_decay',
  priority: 60, display: 'inline', deploy_cost: 1, ace_delta: -12, score_delta: null, warnings: [], fingerprint: 'e'.repeat(64),
};
const SPLIT_DETAIL: RecommendationDetail = {
  ...SPLIT,
  plan: {
    executable: true,
    ops: [
      { op: 'update_rule', rule_name: 'MIXED' },
      { op: 'create_rule', name: 'MIXED_SILVER' },
    ],
  },
  preview: {
    policy: { id: 'p1', name: 'ACP-1', kind: 'access' },
    before: [{ id: 'r12', index: 12, name: 'MIXED', action: 'ALLOW', enabled: true, section: 'Default', category: '', fields: { dst_net: ['NET_GOLD', 'NET_SILVER'] } }],
    after: [
      {
        id: 'r12', index: 12, name: 'MIXED', action: 'ALLOW', enabled: true, section: 'Default', category: '',
        fields: { dst_net: ['NET_GOLD'] }, status: 'modified', changes: { dst_net: { added: [], removed: ['NET_SILVER'] } },
      },
      { id: null, index: null, name: 'MIXED_SILVER', action: 'ALLOW', enabled: true, section: 'Default', category: '', fields: { dst_net: ['NET_SILVER'] }, status: 'new', changes: {} },
    ],
  },
};

function recRoutes(handler: Handler): Handler {
  return (req) => {
    if (req.url.startsWith('/api/snapshots/7/recommendations?')) {
      return {
        status: 200,
        body: {
          total: 2, offset: 0,
          summary: { split_rule: { count: 1, deploy_cost: 2, ace_delta: 0 }, remove_dead_rule: { count: 1, deploy_cost: 1, ace_delta: -12 } },
          accepted: { count: 0, deploy_cost: 0, ace_delta: 0 },
          rows: [SPLIT, REMOVE],
        },
      };
    }
    if (req.url === '/api/snapshots/7/recommendations/5') return { status: 200, body: SPLIT_DETAIL };
    return handler(req);
  };
}

describe('RecommendationsPage', () => {
  it('accepts a whole kind after a preview of its cost', async () => {
    const calls = setup(
      '/recommendations?kind=split_rule',
      <Route path="/recommendations" element={<RecommendationsPage />} />,
      recRoutes((req) => {
        if (req.url === '/api/snapshots/7/recommendations/decisions') {
          return {
            status: 200,
            body: { count: 12, changing: 0, deploy_cost: 240, ace_delta: -80, skipped: { not_executable: 2 }, deploy_limit: 100, batches: 3 },
          };
        }
        return undefined;
      }),
      ['policy:read', 'changeset:write'],
    );
    await userEvent.click(await screen.findByRole('button', { name: 'Accept all: Split rule by destination tier' }));
    const dialog = await screen.findByRole('dialog', { name: 'Confirm a decision for many recommendations' });
    expect(within(dialog).getByText(/Accept 12 recommendations .*240 changes in the FMC, about 3 deploy batches of up to 100/)).toBeInTheDocument();
    expect(within(dialog).getByText(/Left out: 2 \(2 cannot be executed/)).toBeInTheDocument();
    expect(calls.filter((c) => c.url.endsWith('/decisions')).map((c) => c.body)).toEqual([
      { status: 'accepted', kind: 'split_rule', dry_run: true },
    ]);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Accept 12' }));
    expect(await screen.findByText('12 recommendations accepted.')).toBeInTheDocument();
    expect(calls.filter((c) => c.url.endsWith('/decisions')).map((c) => c.body)[1]).toEqual({ status: 'accepted', kind: 'split_rule' });
  });

  it('shows the queue, the inline and split previews, and records a local decision', async () => {
    const calls = setup(
      '/recommendations',
      <Route path="/recommendations" element={<RecommendationsPage />} />,
      recRoutes((req) => {
        if (req.url === '/api/snapshots/7/recommendations/5/decision') {
          return { status: 200, body: { ...SPLIT, decision: { status: 'accepted', note: 'CHG-1', decided_by: 'opt', decided_at: '2026-10-20T12:00:00Z' } } };
        }
        return undefined;
      }),
      ['policy:read', 'changeset:write'],
    );
    expect(await screen.findByText(SPLIT.title)).toBeInTheDocument();
    const kinds = screen.getByRole('group', { name: 'Type' });
    expect(within(kinds).getByRole('button', { name: /Split rule by destination tier/ })).toBeInTheDocument();
    expect(screen.getByText('−12 ACEs')).toBeInTheDocument();
    expect(screen.getByText('Score +25')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: SPLIT.title }));
    // Structural change: opens in before/after mode.
    expect(await screen.findByRole('button', { name: 'Before / after', pressed: true })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Before' })).toBeInTheDocument();
    expect(screen.getByText('MIXED_SILVER')).toBeInTheDocument();
    // Known warnings are translated; unknown codes are shown as-is.
    expect(screen.getByText('Part of the addresses is not in the asset table.')).toBeInTheDocument();
    expect(screen.getByText('brand_new_code')).toBeInTheDocument();
    expect(screen.getByText('One destination tier per rule')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Inline' }));
    const removed = screen.getByText('NET_SILVER', { selector: 'del bdi' });
    expect(removed.closest('del')).toHaveClass('diff-del');
    expect(screen.getAllByText('New').length).toBeGreaterThan(0);

    await userEvent.type(screen.getByLabelText('Note (e.g. ticket)'), 'CHG-1');
    await userEvent.click(screen.getByRole('button', { name: 'Accept' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'PUT')).toBe(true);
    });
    const put = calls.find((c) => c.method === 'PUT');
    expect(put?.url).toBe('/api/snapshots/7/recommendations/5/decision');
    expect(put?.body).toEqual({ status: 'accepted', note: 'CHG-1' });
    expect(put?.headers['X-CSRF-Token']).toBe('csrf-3');
  });

  it('is read-only without the changeset permission', async () => {
    setup(
      '/recommendations?rec=5',
      <Route path="/recommendations" element={<RecommendationsPage />} />,
      recRoutes(() => undefined),
      ['policy:read'],
    );
    expect(await screen.findByText('MIXED_SILVER')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Accept' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Re-run analysis' })).not.toBeInTheDocument();
  });
});

describe('NamingPage', () => {
  it('saves a template and shows server validation errors', async () => {
    let attempt = 0;
    const calls = setup(
      '/naming',
      <Route path="/naming" element={<NamingPage />} />,
      (req) => {
        if (req.url === '/api/naming-conventions' && req.method === 'GET') {
          return {
            status: 200,
            body: {
              kinds: { host: ['VALUE'], network: ['VALUE'], range: ['VALUE'], fqdn: ['VALUE'], network_group: ['ROLE', 'TIER'], port: ['PORT'], port_group: ['SVC'], rule: ['DST', 'SRC', 'SVC'] },
              conventions: [{ kind: 'network_group', template: 'GRP_<ROLE>', letter_case: 'upper', enabled: true, updated_by: 'admin', updated_at: '2026-10-20T10:00:00Z' }],
            },
          };
        }
        if (req.url === '/api/naming-conventions/rule' && req.method === 'PUT') {
          attempt += 1;
          return attempt === 1
            ? { status: 422, body: { detail: 'template_adjacent_tokens' } }
            : { status: 200, body: { kind: 'rule', template: '<SRC>_TO_<DST>_<SVC>', letter_case: 'upper', enabled: true, updated_by: 'admin', updated_at: '2026-10-20T10:00:00Z' } };
        }
        return undefined;
      },
      ['policy:read', 'conventions:manage'],
    );
    expect(await screen.findByDisplayValue('GRP_<ROLE>')).toBeInTheDocument();
    expect(screen.getByText('4 compliant · 9 non-compliant · 6 renames proposed')).toBeInTheDocument();
    const box = screen.getByLabelText('Template — Access rule');
    await userEvent.type(box, '<SRC><DST>');
    const row = box.closest('tr');
    expect(row).not.toBeNull();
    if (row === null) return;
    await userEvent.click(within(row).getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Separate tokens with a character (e.g. _).')).toBeInTheDocument();
    await userEvent.clear(box);
    await userEvent.type(box, '<SRC>_TO_<DST>_<SVC>');
    await userEvent.click(within(row).getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/Convention saved/)).toBeInTheDocument();
    const puts = calls.filter((c) => c.method === 'PUT');
    expect(puts[1]?.body).toEqual({ template: '<SRC>_TO_<DST>_<SVC>', letter_case: 'upper', enabled: true });
  });

  it('is read-only for viewers', async () => {
    setup(
      '/naming',
      <Route path="/naming" element={<NamingPage />} />,
      (req) =>
        req.url === '/api/naming-conventions'
          ? { status: 200, body: { kinds: { network_group: ['ROLE'] }, conventions: [{ kind: 'network_group', template: 'GRP_<ROLE>', letter_case: 'upper', enabled: true, updated_by: 'admin', updated_at: '2026-10-20T10:00:00Z' }] } }
          : undefined,
      ['policy:read'],
    );
    expect(await screen.findByText('GRP_<ROLE>')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
  });
});

describe('Policy editor recommendation tags', () => {
  beforeEach(() => {
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue(DOMRect.fromRect({ x: 0, y: 0, width: 1200, height: 800 }));
    vi.spyOn(HTMLElement.prototype, 'offsetHeight', 'get').mockReturnValue(800);
    vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockReturnValue(1200);
  });

  it('tags rules with their recommendation type and deploy cost', async () => {
    const row: RuleRow = {
      id: 'r12', rule_type: null, index: 12, section: 'Default', category: '', name: 'MIXED', enabled: true,
      action: 'ALLOW', hit_count: 3, last_hit: null, ips_policy: null, file_policy: null, log_begin: false, log_end: true,
      refs: {}, recommendations: [{ id: 5, kind: 'split_rule', deploy_cost: 2, status: 'open' }],
    };
    setup(
      '/rules',
      <Route path="/rules" element={<RulebasePage />} />,
      (req) => {
        if (req.url === '/api/snapshots/7/clusters') {
          return { status: 200, body: [{ fmc_id: 'c1', name: 'C', kind: 'ha_pair', sw_version: '', model: '', members: [], policy_fmc_id: 'p1', policy_name: 'ACP', rule_count: 1, ace_total: 1, ace_limit: 10, ace_limit_verified: false, policies: [{ id: 'p1', name: 'ACP', kind: 'access', via: 'assignment', rule_count: 1 }] }] };
        }
        if (req.url.includes('/rules?')) {
          return { status: 200, body: { policy_fmc_id: 'p1', policy_kind: 'access', policy_name: 'ACP', default_action: 'BLOCK', groups: [], categories: [], total: 1, offset: 0, rows: [row] } };
        }
        return undefined;
      },
      ['policy:read'],
    );
    const tag = await screen.findByRole('link', { name: 'Split rule by destination tier · 2 changes · Open' });
    expect(tag).toHaveAttribute('href', '/recommendations?snapshot=7&rec=5');
    expect(tag).toHaveTextContent('Split2');
  });

  it('switching the cluster resets the policy in one URL update', async () => {
    const cluster = (id: string, policy: string) => ({
      fmc_id: id, name: id.toUpperCase(), kind: 'ha_pair', sw_version: '', model: '', members: [], policy_fmc_id: policy,
      policy_name: policy, rule_count: 0, ace_total: 0, ace_limit: 1, ace_limit_verified: false,
      policies: [{ id: policy, name: `ACP-${policy}`, kind: 'access', via: 'assignment', rule_count: 0 }],
    });
    const page = (policy: string) => ({
      policy_fmc_id: policy, policy_kind: 'access', policy_name: `ACP-${policy}`, default_action: 'BLOCK',
      groups: [], categories: [], total: 0, offset: 0, rows: [],
    });
    const calls = setup(
      '/rules?cluster=c1&policy=p1',
      <Route path="/rules" element={<RulebasePage />} />,
      (req) => {
        if (req.url === '/api/snapshots/7/clusters') return { status: 200, body: [cluster('c1', 'p1'), cluster('c2', 'p2')] };
        if (req.url.startsWith('/api/snapshots/7/policies/p1/rules')) return { status: 200, body: page('p1') };
        if (req.url.startsWith('/api/snapshots/7/policies/p2/rules')) return { status: 200, body: page('p2') };
        return undefined;
      },
      ['policy:read'],
    );
    expect(await screen.findByRole('heading', { name: 'ACP-p1' })).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText('Cluster'), 'c2');
    expect(await screen.findByRole('heading', { name: 'ACP-p2' })).toBeInTheDocument();
    expect(calls.some((c) => c.url.startsWith('/api/snapshots/7/policies/p2/rules'))).toBe(true);
  });
});
