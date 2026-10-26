import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { Me, ObjectDetail, Snapshot } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import type { Recorded } from '../test/fetchMock';
import { ObjectExplorerPage } from './ObjectExplorerPage';

const ME: Me = {
  id: 1, username: 'v', display_name: 'V', auth_provider: 'local', roles: ['viewer'], permissions: ['policy:read'],
  language: 'en', theme: 'system', must_change_password: false, csrf_token: 'c',
};
const SNAP = {
  id: 7, connection_id: 1, connection_name: 'FMC', status: 'complete', requested_by: 'x', created_at: '2026-10-27T10:00:00Z',
  started_at: null, finished_at: null, analyzed_at: '2026-10-27T10:05:00Z', fmc_version: null, error: null, error_detail: null, stats: {},
} satisfies Snapshot;

const obj = (id: string, name: string, kind: string, value: string | null, extra: Partial<{ rule_refs: number; member_of: number }> = {}) => ({
  id, name, kind, fmc_type: kind, value, stub: false, rule_refs: extra.rule_refs ?? 0, member_of: extra.member_of ?? 0,
});
const node = (id: string, name: string, kind: string, members: number, memberOf: number, refs = 0) => ({
  id, name, kind, value: null, members, member_of: memberOf, rule_refs: refs, read_only: false,
});

function detail(id: string, name: string): ObjectDetail {
  return {
    object: obj(id, name, 'host', '10.20.5.77/32', { rule_refs: 1, member_of: 2 }),
    attrs: {},
    members: [],
    member_of: [],
    used_by: [
      {
        policy_fmc_id: 'p1', policy_kind: 'access', policy_name: 'ACP', rule_id: 'r1', rule_index: 12,
        rule_name: 'CHAIN_RULE', field: 'dst_net', via_id: 'g6', via_name: 'GRP_CHAIN_6',
      },
    ],
    used_by_total: 1,
  };
}

function setup(path: string): Recorded[] {
  const calls = mockFetch((req) => {
    const url = req.url;
    if (url === '/api/auth/me') return { status: 200, body: ME };
    if (url.startsWith('/api/snapshots?')) return { status: 200, body: [SNAP] };
    if (url.startsWith('/api/snapshots/7/objects?')) {
      return { status: 200, body: { total: 2, offset: 0, rows: [obj('x', 'H_CHAIN_X', 'host', '10.20.5.77/32'), obj('g1', 'GRP_CHAIN_1', 'network_group', null)] } };
    }
    if (url.startsWith('/api/snapshots/7/objects/x/tree?direction=up&offset=0')) {
      return { status: 200, body: { parent: 'x', direction: 'up', total: 3, offset: 0, nodes: [node('g1', 'GRP_CHAIN_1', 'network_group', 1, 1), node('g3', 'GRP_CHAIN_3', 'network_group', 2, 1)] } };
    }
    if (url.startsWith('/api/snapshots/7/objects/x/tree?direction=up&offset=2')) {
      return { status: 200, body: { parent: 'x', direction: 'up', total: 3, offset: 2, nodes: [node('g9', 'GRP_OTHER', 'network_group', 1, 0)] } };
    }
    if (url.startsWith('/api/snapshots/7/objects/x/tree?direction=down')) {
      return { status: 200, body: { parent: 'x', direction: 'down', total: 0, offset: 0, nodes: [] } };
    }
    if (url.startsWith('/api/snapshots/7/objects/g1/tree?direction=up')) {
      return { status: 200, body: { parent: 'g1', direction: 'up', total: 1, offset: 0, nodes: [node('g2', 'GRP_CHAIN_2', 'network_group', 1, 0, 3)] } };
    }
    if (url.startsWith('/api/snapshots/7/objects/x/relations')) {
      return {
        status: 200,
        body: {
          object: { id: 'x', name: 'H_CHAIN_X', kind: 'host', value: '10.20.5.77/32' }, nodes: [], edges: [], truncated: false,
          issues: [{ kind: 'redundant_member', where_id: 'g3', where_name: 'GRP_CHAIN_3', removed: 'H_CHAIN_X', kept: 'GRP_CHAIN_2', recommendation_id: 41 }],
        },
      };
    }
    if (url.startsWith('/api/snapshots/7/objects/x')) return { status: 200, body: detail('x', 'H_CHAIN_X') };
    return { status: 404, body: { detail: 'not_found' } };
  });
  render(
    <I18nProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route path="/objects/explore" element={<ObjectExplorerPage />} />
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </I18nProvider>,
  );
  return calls;
}

describe('ObjectExplorerPage', () => {
  it('walks the tree level by level, pages large levels and explains the selected object', async () => {
    const calls = setup('/objects/explore?snapshot=7&object=x');
    const tree = await screen.findByRole('tree');
    expect(await within(tree).findByText('GRP_CHAIN_1')).toBeInTheDocument();
    expect(within(tree).getByText('No members.')).toBeInTheDocument();
    // Levels load only when opened.
    expect(calls.some((c) => c.url.includes('/objects/g1/tree'))).toBe(false);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Expand GRP_CHAIN_1' }));
    expect(await within(tree).findByText('GRP_CHAIN_2')).toBeInTheDocument();
    expect(within(tree).getByText('3 rule refs')).toBeInTheDocument();
    // A large level is paged.
    await user.click(screen.getByRole('button', { name: 'Load more (1 left)' }));
    expect(await within(tree).findByText('GRP_OTHER')).toBeInTheDocument();
    // Details of the root: rules grouped by the level they use, redundant links with their fix.
    expect(await screen.findByText('Through the group GRP_CHAIN_6')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Fix →' })).toHaveAttribute('href', '/recommendations?snapshot=7&rec=41');
  });

  it('starts from the search list', async () => {
    setup('/objects/explore?snapshot=7');
    expect(await screen.findByText('Search on the side and pick an object to explore.')).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /H_CHAIN_X/ }));
    expect(await screen.findByRole('tree')).toBeInTheDocument();
  });
});
