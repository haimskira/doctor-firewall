import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { act } from 'react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { ConnectivityMap, DashboardData, Me, Snapshot } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { layoutFlows, riskParts } from '../components/FlowSankey';
import { columnGap, elementsFor, RISK_COLOURS } from '../components/Graph';
import { MapChange } from '../components/mapParts';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import type { Recorded } from '../test/fetchMock';
import { HomePage } from './HomePage';
import { MapPage } from './MapPage';

// jsdom has no canvas: a fake Cytoscape records what the page gives it.
type TapHandler = (event: ReturnType<typeof target>) => void;
const fake = vi.hoisted(() => ({
  added: [] as unknown[],
  handlers: new Map<string, TapHandler>(),
  instances: 0,
}));
vi.mock('cytoscape', () => {
  // A chainable collection: every method returns the collection itself.
  const collection: Record<string, () => unknown> = Object.fromEntries(
    ['remove', 'removeClass', 'addClass', 'difference', 'union'].map((m) => [m, () => collection]),
  );
  return {
    default: vi.fn(() => {
      fake.instances += 1;
      return {
        // Handlers are registered as (event, selector, handler) or (event, handler).
        on: (event: string, selector: string | TapHandler, handler?: TapHandler) => {
          if (typeof selector === 'string' && handler !== undefined) fake.handlers.set(`${event}:${selector}`, handler);
        },
        elements: () => collection,
        batch: (fn: () => void) => {
          fn();
        },
        add: (items: unknown[]) => {
          fake.added = items;
        },
        fit: vi.fn(),
        resize: vi.fn(),
        style: vi.fn(),
        destroy: vi.fn(),
      };
    }),
  };
});

/** A tapped element as Cytoscape passes it to handlers. */
function target(id: string, node: boolean) {
  const self = { id: () => id, isNode: () => node, connectedNodes: () => self, closedNeighborhood: () => self, union: () => self, addClass: () => self };
  return { target: self };
}

const ME: Me = {
  id: 1, username: 'v', display_name: 'V', roles: ['viewer'], permissions: ['policy:read'], language: 'en',
  auth_provider: 'local', must_change_password: false, theme: 'system', csrf_token: 'c',
};
const SNAP = {
  id: 7, connection_id: 1, connection_name: 'FMC', status: 'complete', requested_by: 'x', created_at: '2026-10-20T10:00:00Z',
  started_at: null, finished_at: null, analyzed_at: '2026-10-20T11:00:00Z', fmc_version: null, error: null, error_detail: null, stats: {},
} satisfies Snapshot;
const MAP: ConnectivityMap = {
  view: 'assets',
  nodes: [
    { id: 'BRONZE|DEV', label: 'DEV', tier: 'BRONZE', user_type: null, networks: ['10.40.0.0/16'] },
    { id: 'GOLD|SQL-FIN', label: 'SQL-FIN', tier: 'GOLD', user_type: null, networks: ['10.20.5.0/24'] },
    { id: 'ANY', label: 'ANY', tier: null, user_type: null, networks: [] },
  ],
  edges: [
    {
      id: 'BRONZE|DEV->GOLD|SQL-FIN', src: 'BRONZE|DEV', dst: 'GOLD|SQL-FIN', risk: 'red', rule_count: 2, hits: 1500, min_score: 25,
      reasons: ['tier_skip', 'gold_without_ips'], services: ['SVC_TCP1433'],
      rules: [{ id: 'r9', name: 'TEMP_DEV_TO_DB', index: 9, risk: 'red', score: 25, policy_id: 'p1' }],
      risk_rules: { red: 1, green: 1 }, risk_hits: { red: 1000, green: 500 },
    },
    {
      id: 'ANY->GOLD|SQL-FIN', src: 'ANY', dst: 'GOLD|SQL-FIN', risk: 'yellow', rule_count: 1, hits: 0, min_score: 60,
      reasons: ['any_source'], services: ['HTTPS'], rules: [{ id: 'r3', name: 'WEB', index: 3, risk: 'yellow', score: 60, policy_id: 'p1' }],
      risk_rules: { yellow: 1 }, risk_hits: {},
    },
  ],
  total_edges: 2,
  truncated: false,
  risk_counts: { red: 1, yellow: 1, green: 0 },
};

function setup(path: string, routes: ReactNode, handler: (req: Recorded) => { status: number; body?: unknown } | undefined): Recorded[] {
  const calls = mockFetch((req) => {
    if (req.url === '/api/auth/me') return { status: 200, body: ME };
    if (req.url.startsWith('/api/snapshots?')) return { status: 200, body: [SNAP] };
    if (req.url === '/api/snapshots/7/clusters') return { status: 200, body: [] };
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

beforeEach(() => {
  fake.added = [];
  fake.handlers.clear();
  fake.instances = 0;
});

describe('Graph layout', () => {
  it('places tiers in columns, mirrors for RTL and colours edges by risk', () => {
    const nodes = MAP.nodes.map((n) => ({ id: n.id, label: n.label, tier: n.tier }));
    const edges = MAP.edges.map((e) => ({ id: e.id, src: e.src, dst: e.dst, risk: e.risk, weight: e.rule_count }));
    const ltr = elementsFor(nodes, edges, false);
    const x = (els: typeof ltr, id: string) => els.find((e) => e.data.id === id)?.position?.x;
    expect(ltr.filter((e) => e.classes === 'column').map((e) => e.data.id)).toEqual(['col:ANY', 'col:BRONZE', 'col:GOLD']);
    const anyX = x(ltr, 'ANY') ?? 0;
    const devX = x(ltr, 'BRONZE|DEV') ?? 0;
    const goldX = x(ltr, 'GOLD|SQL-FIN') ?? 0;
    expect(anyX < devX && devX < goldX).toBe(true);
    const rtl = elementsFor(nodes, edges, true);
    expect(x(rtl, 'GOLD|SQL-FIN')).toBe(-goldX);
    const red = ltr.find((e) => e.data.id === 'BRONZE|DEV->GOLD|SQL-FIN');
    expect(red?.data['colour']).toBe(RISK_COLOURS.red);
    expect(red?.data.source).toBe('BRONZE|DEV');
    expect(ltr.find((e) => e.data.id === 'ANY')?.classes).toBe('special');
  });

  it('fits the column distance to the canvas width within readable bounds', () => {
    expect(columnGap(1200, 7)).toBe(166);
    expect(columnGap(600, 7)).toBe(135);
    expect(columnGap(3000, 3)).toBe(250);
    expect(columnGap(0, 5)).toBe(250);
    const nodes = [{ id: 'ANY', label: 'Any', tier: null }, { id: 'GOLD|X', label: 'X', tier: 'GOLD' }];
    expect(elementsFor(nodes, [], false, undefined, 140).find((e) => e.data.id === 'GOLD|X')?.position?.x).toBe(140);
  });
});

describe('MapPage', () => {
  it('renders the graph and list, filters by address and risk, and explains a connection', async () => {
    const calls = setup('/map?mode=graph', <Route path="/map" element={<MapPage />} />, (req) => {
      if (req.url.startsWith('/api/snapshots/7/map?')) {
        if (req.url.includes('src=bogus')) return { status: 422, body: { detail: 'invalid_src' } };
        return { status: 200, body: MAP };
      }
      return undefined;
    });
    expect(await screen.findByText('Dangerous (1)')).toBeInTheDocument();
    expect(screen.getByText('2 connections')).toBeInTheDocument();
    await waitFor(() => {
      expect(fake.added.length).toBeGreaterThan(0);
    });
    expect(screen.getByRole('img', { name: 'Connectivity graph' })).toBeInTheDocument();

    // Click in the list.
    const table = screen.getByRole('table');
    await userEvent.click(within(table).getByRole('button', { name: 'DEV' }));
    expect(screen.getByRole('heading', { name: 'DEV → SQL-FIN' })).toBeInTheDocument();
    expect(screen.getByText('Skips tiers')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '#9 TEMP_DEV_TO_DB' })).toHaveAttribute(
      'href',
      '/rules?snapshot=7&policy=p1&q=TEMP_DEV_TO_DB',
    );
    // Tap in the graph.
    act(() => {
      fake.handlers.get('tap:edge')?.(target('ANY->GOLD|SQL-FIN', false));
    });
    expect(screen.getByRole('heading', { name: 'Any → SQL-FIN' })).toBeInTheDocument();
    act(() => {
      fake.handlers.get('tap:node.system, node.special')?.(target('GOLD|SQL-FIN', true));
    });
    expect(screen.getByText('10.20.5.0/24')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('tab', { name: 'System to system' }));
    await waitFor(() => {
      expect(calls.some((c) => c.url.includes('view=system'))).toBe(true);
    });
    await userEvent.type(screen.getByLabelText('From (IP / subnet / range)'), '10.40.0.0/16');
    await userEvent.click(screen.getByLabelText('Both directions'));
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }));
    await waitFor(() => {
      expect(calls.some((c) => c.url.includes('src=10.40.0.0%2F16') && c.url.includes('both=true'))).toBe(true);
    });
    await userEvent.click(screen.getByLabelText(/Compliant/));
    await waitFor(() => {
      expect(calls.some((c) => c.url.includes('risk=red&risk=yellow') || c.url.includes('risk=yellow&risk=red'))).toBe(true);
    });

    await userEvent.clear(screen.getByLabelText('From (IP / subnet / range)'));
    await userEvent.type(screen.getByLabelText('From (IP / subnet / range)'), 'bogus');
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }));
    expect(await screen.findByText('The source is not a valid IP, subnet or range.')).toBeInTheDocument();
  });
});

describe('Recommendation map before / after', () => {
  it('shows both sides and an empty after for a removal', () => {
    render(
      <I18nProvider initial="en">
        <MapChange before={[{ src: 'BRONZE|DEV', dst: 'GOLD|SQL-FIN', risk: 'red' }]} after={[]} />
      </I18nProvider>,
    );
    expect(screen.getByRole('heading', { name: 'Map before / after' })).toBeInTheDocument();
    expect(screen.getByText('DEV')).toBeInTheDocument();
    expect(screen.getByText('No connection (the rule is removed or never matches).')).toBeInTheDocument();
    expect(fake.instances).toBe(1);
  });
});

describe('Summary dashboard', () => {
  const DASH: DashboardData = {
    snapshot: { id: 7, connection_name: 'FMC-HA', fmc_version: '10.1.0', created_at: '2026-10-20T10:00:00Z', finished_at: '2026-10-20T10:05:00Z', analyzed_at: '2026-10-20T10:06:00Z' },
    totals: { rules: 6220, policies: 30, objects: 110, clusters: 3, findings: 12, recommendations: 9, dead_rules: 4, shadowed_rules: 2 },
    findings_by_severity: { high: 3, medium: 5, low: 4, info: 0 },
    findings_by_kind: [{ key: 'shadowed_rule', count: 7, extra: {} }, { key: 'dead_rule', count: 5, extra: {} }],
    recommendations_by_kind: [{ key: 'split_rule', count: 9, extra: { deploy_cost: 18, ace_delta: 0 } }],
    score_buckets: [{ key: '0-19', count: 1, extra: {} }, { key: '20-39', count: 2, extra: {} }, { key: '40-59', count: 3, extra: {} }, { key: '60-79', count: 4, extra: {} }, { key: '80-100', count: 5, extra: {} }],
    rules_by_action: [{ key: 'ALLOW', count: 6000, extra: {} }, { key: 'BLOCK', count: 220, extra: {} }],
    clusters: [{ id: 'c1', name: 'FTD-CL01', rule_count: 2000, ace_total: 900_000, ace_limit: 1_000_000, ace_limit_verified: false }],
    map_risk: { red: 2, yellow: 3, green: 1 },
    riskiest_connections: [{ src: 'BRONZE|DEV', dst: 'GOLD|SQL-FIN', risk: 'red', rule_count: 2, hits: 10 }],
    worst_rules: [{ id: 'r9', name: 'ANY_ANY_TEMP', index: 9, policy_id: 'p1', policy_name: 'ACP', score: 5 }],
  };

  it('shows widgets per tab, and widgets can be closed and added back', async () => {
    setup('/', <Route path="/" element={<HomePage />} />, (req) =>
      req.url === '/api/snapshots/7/dashboard' ? { status: 200, body: DASH } : undefined,
    );
    expect(await screen.findByRole('heading', { name: 'Summary Dashboard' })).toBeInTheDocument();
    const findings = await screen.findByRole('region', { name: 'Top Findings' });
    expect(within(findings).getByRole('link', { name: 'Shadowed rules' })).toHaveAttribute('href', '/findings?snapshot=7&kind=shadowed_rule');
    expect(within(screen.getByRole('region', { name: 'ACE Usage by Cluster' })).getByText('90% *')).toBeInTheDocument();
    expect(within(screen.getByRole('region', { name: 'Estate at a Glance' })).getByText('6,220')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Close Top Findings' }));
    expect(screen.queryByRole('region', { name: 'Top Findings' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Add Widgets' }));
    await userEvent.click(screen.getByRole('menuitem', { name: 'Top Findings' }));
    expect(screen.getByRole('region', { name: 'Top Findings' })).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Minimise Estate at a Glance' }));
    expect(within(screen.getByRole('region', { name: 'Estate at a Glance' })).queryByText('6,220')).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('tab', { name: 'Risk' }));
    const conn = screen.getByRole('region', { name: 'Riskiest Connections' });
    expect(within(conn).getByText('DEV')).toBeInTheDocument();
    expect(within(screen.getByRole('region', { name: 'Lowest-Scored Rules' })).getByText('5')).toBeInTheDocument();
  });
});

describe('Flow view', () => {
  const edges = MAP.edges.map((e) => ({
    id: e.id, src: e.src, dst: e.dst, ruleCount: e.rule_count, hits: e.hits,
    riskRules: e.risk_rules, riskHits: e.risk_hits, fallbackRisk: e.risk,
  }));
  const nodes = MAP.nodes.map((n) => ({ id: n.id, label: n.label, tier: n.tier }));

  it('splits every connection by risk instead of painting it with the worst rule', () => {
    const dev = edges.find((e) => e.src === 'BRONZE|DEV');
    if (dev === undefined) throw new Error('fixture');
    expect(riskParts(dev, 'rules')).toEqual([['red', 1], ['green', 1]]);
    expect(riskParts(dev, 'hits')).toEqual([['red', 1000], ['green', 500]]);
    const any = edges.find((e) => e.src === 'ANY');
    if (any === undefined) throw new Error('fixture');
    expect(riskParts(any, 'hits')).toEqual([]); // no hits: nothing to draw by hits
    const layout = layoutFlows(nodes, edges, 'rules', 900, 400, false, (n) => `+${String(n)}`);
    expect(layout.sources.map((s) => s.id).sort()).toEqual(['ANY', 'BRONZE|DEV']);
    expect(layout.targets.map((d) => d.id)).toEqual(['GOLD|SQL-FIN']);
    expect(layout.bands.map((b) => b.risk).sort()).toEqual(['green', 'red', 'yellow']);
    const mirrored = layoutFlows(nodes, edges, 'rules', 900, 400, true, (n) => `+${String(n)}`);
    expect(mirrored.bands[0]?.path).not.toEqual(layout.bands[0]?.path);
  });

  it('is the default display, with insights, and opens a connection from a flow', async () => {
    setup('/map', <Route path="/map" element={<MapPage />} />, (req) => {
      if (req.url.startsWith('/api/snapshots/7/map?')) return { status: 200, body: MAP };
      return undefined;
    });
    expect(await screen.findByRole('img', { name: 'Connection flows by risk' })).toBeInTheDocument();
    expect(screen.getByText('Riskiest connections')).toBeInTheDocument();
    expect(screen.getByText('1 risky rules')).toBeInTheDocument();
    const band = document.querySelector('path.flow-band.risk-red');
    expect(band).not.toBeNull();
    if (band === null) return;
    await userEvent.click(band);
    expect(await screen.findByText('TEMP_DEV_TO_DB')).toBeInTheDocument();
    const by = screen.getByRole('group', { name: 'Width by' });
    await userEvent.click(within(by).getByRole('button', { name: 'Hits' }));
    expect(document.querySelector('path.flow-band.risk-yellow')).toBeNull(); // the yellow rule has no hits
  });
});
