import { useCallback, useMemo, useState } from 'react';
import type { SyntheticEvent } from 'react';
import { Link } from 'react-router-dom';
import { SortedTable } from '../components/sort';

import type { Cluster, ConnectivityMap, MapEdge, MapNode, MapRisk, MapView } from '../api/types';
import { Alert, Ltr } from '../components/common';
import { FlowInsights } from '../components/FlowInsights';
import { FlowSankey } from '../components/FlowSankey';
import type { FlowMetric } from '../components/FlowSankey';
import { Graph } from '../components/Graph';
import { SnapshotPicker } from '../components/inventory';
import { RiskBadge, useColumnLabel, useNodeLabel, useReasonLabel } from '../components/mapParts';
import { useApi, useQueryParam, useSetQueryParams, useSnapshotSelection } from '../hooks';
import { PolicyPicker, ScopeNote, usePolicyScope } from '../components/policyScope';
import { useI18n } from '../i18n/I18nProvider';

const VIEWS: readonly MapView[] = ['assets', 'system', 'users'];
const RISKS: readonly MapRisk[] = ['red', 'yellow', 'green'];
const RISK_RANK: Record<MapRisk, number> = { green: 0, yellow: 1, red: 2 };
const LIST_LIMIT = 200;
type Mode = 'flows' | 'graph';

/**
 * Connectivity map: three views (assets / system-to-system / users-to-systems), filters by
 * cluster, address (either direction) and risk; click a connection to see its rules.
 */
export function MapPage() {
  const { t, tError, dir } = useI18n();
  const { snapshots, snapshotId, setSnapshotId, error: snapError } = useSnapshotSelection();
  const [viewParam, setView] = useQueryParam('view');
  const [cluster, setCluster] = useQueryParam('cluster');
  const [src] = useQueryParam('src');
  const [dst] = useQueryParam('dst');
  const [bothParam] = useQueryParam('both');
  const setParams = useSetQueryParams();
  const [riskParam, setRisk] = useQueryParam('risk');
  const [modeParam, setMode] = useQueryParam('mode');
  const [byParam, setBy] = useQueryParam('by');
  const mode: Mode = modeParam === 'graph' ? 'graph' : 'flows';
  const metric: FlowMetric = byParam === 'hits' ? 'hits' : 'rules';
  const view: MapView = VIEWS.find((v) => v === viewParam) ?? 'assets';
  const risks = (riskParam ?? '').split(',').filter((r): r is MapRisk => RISKS.some((x) => x === r));
  const [form, setForm] = useState({ src: src ?? '', dst: dst ?? '', both: bothParam === '1' });
  const [selected, setSelected] = useState<{ kind: 'edge' | 'node'; id: string } | null>(null);

  const clusters = useApi<Cluster[]>(snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}/clusters`);
  const scope = usePolicyScope(snapshotId);
  const params = new URLSearchParams({ view });
  if (scope.policy !== null) params.set('policy', scope.policy);
  if (cluster !== null) params.set('cluster', cluster);
  if (src !== null) params.set('src', src);
  if (dst !== null) params.set('dst', dst);
  if (bothParam === '1') params.set('both', 'true');
  if (mode === 'graph') for (const r of risks) params.append('risk', r);
  const map = useApi<ConnectivityMap>(snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}/map?${params.toString()}`);
  const data = map.data;
  const nodeLabel = useNodeLabel();
  const columnLabel = useColumnLabel();

  const graphNodes = useMemo(
    () => (data?.nodes ?? []).map((n) => ({ id: n.id, tier: n.tier, label: nodeLabel(n.id, n.label) })),
    [data, nodeLabel],
  );
  // Colours shown in the flow view (no parameter: all); a plain string keeps memoisation stable.
  const shownKey = riskParam ?? RISKS.join(',');
  const flowNodes = useMemo(
    () => (data?.nodes ?? []).map((n) => ({ id: n.id, tier: n.tier, label: nodeLabel(n.id, n.label) })),
    [data, nodeLabel],
  );
  const flowEdges = useMemo(() => {
    const visible = new Set(shownKey.split(','));
    const shownOnly = (parts: Partial<Record<MapRisk, number>>) =>
      Object.fromEntries(Object.entries(parts).filter(([r]) => visible.has(r)));
    return (data?.edges ?? []).map((e) => ({
        id: e.id,
        src: e.src,
        dst: e.dst,
        ruleCount: e.rule_count,
        hits: e.hits,
        riskRules: shownOnly(e.risk_rules),
        riskHits: shownOnly(e.risk_hits),
        fallbackRisk: e.risk,
      }));
  }, [data, shownKey]);
  // Rules per risk colour over the whole view (the flow legend counts rules, not connections).
  const ruleCounts = useMemo(() => {
    const out = new Map<MapRisk, number>();
    for (const e of data?.edges ?? []) {
      const parts = Object.entries(e.risk_rules);
      if (parts.length === 0) out.set(e.risk, (out.get(e.risk) ?? 0) + e.rule_count);
      for (const [r, n] of parts) {
        const risk = RISKS.find((x) => x === r);
        if (risk !== undefined) out.set(risk, (out.get(risk) ?? 0) + n);
      }
    }
    return out;
  }, [data]);
  const otherLabel = useCallback((count: number) => t('map.others', { count }), [t]);
  const describe = useCallback(
    (b: { src: string; dst: string; risk: MapRisk; value: number }) =>
      t(metric === 'hits' ? 'map.flowHits' : 'map.flowRules', {
        from: b.src === '__other__' ? t('map.othersShort') : nodeLabel(b.src),
        to: b.dst === '__other__' ? t('map.othersShort') : nodeLabel(b.dst),
        risk: t(`map.risk.${b.risk}`),
        count: b.value.toLocaleString(),
      }),
    [t, metric, nodeLabel],
  );
  const graphEdges = useMemo(
    () => (data?.edges ?? []).map((e) => ({ id: e.id, src: e.src, dst: e.dst, risk: e.risk, weight: e.rule_count })),
    [data],
  );

  function apply(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    setParams({
      src: form.src.trim() === '' ? null : form.src.trim(),
      dst: form.dst.trim() === '' ? null : form.dst.trim(),
      both: form.both ? '1' : null,
    });
    setSelected(null);
  }

  function toggleRisk(r: MapRisk) {
    // No risk parameter means all risks are shown (all boxes checked).
    const shown = risks.length === 0 ? [...RISKS] : risks;
    const next = shown.includes(r) ? shown.filter((x) => x !== r) : [...shown, r];
    setRisk(next.length === 0 || next.length === RISKS.length ? null : next.join(','));
    setSelected(null);
  }

  const edge = selected?.kind === 'edge' ? data?.edges.find((e) => e.id === selected.id) : undefined;
  const node = selected?.kind === 'node' ? data?.nodes.find((n) => n.id === selected.id) : undefined;
  const error = snapError ?? clusters.error ?? map.error;

  return (
    <div className="stack">
      <div className="row spread">
        <div>
          <h1>{t('map.title')}</h1>
          <p className="muted small">{t('map.help')}</p>
        </div>
        <SnapshotPicker snapshots={snapshots} value={snapshotId} onChange={setSnapshotId} />
        <PolicyPicker scope={scope} />
      </div>
      <ScopeNote scope={scope} traffic />
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      {snapshotId === null && snapError === null && <Alert kind="info">{t('snap.none')}</Alert>}

      <div className="pe-flow" role="tablist" aria-label={t('map.view')}>
        {VIEWS.map((v) => (
          <button
            key={v}
            type="button"
            role="tab"
            aria-selected={view === v}
            className={view === v ? 'active' : ''}
            onClick={() => {
              setView(v === 'assets' ? null : v);
              setSelected(null);
            }}
          >
            {t(`map.view.${v}`)}
          </button>
        ))}
      </div>

      <form className="pe-toolbar card-toolbar map-filters" onSubmit={apply}>
        <label className="inline-field">
          {t('rules.cluster')}
          <select
            value={cluster ?? ''}
            onChange={(e) => {
              setCluster(e.target.value === '' ? null : e.target.value);
              setSelected(null);
            }}
          >
            <option value="">{t('map.allClusters')}</option>
            {(clusters.data ?? []).map((c) => (
              <option key={c.fmc_id} value={c.fmc_id}>
                {c.name}
              </option>
            ))}
          </select>
        </label>
        <label className="inline-field">
          {t('map.from')}
          <input
            dir="ltr"
            className="ltr"
            maxLength={96}
            value={form.src}
            onChange={(e) => {
              setForm({ ...form, src: e.target.value });
            }}
          />
        </label>
        <label className="inline-field">
          {t('map.to')}
          <input
            dir="ltr"
            className="ltr"
            maxLength={96}
            value={form.dst}
            onChange={(e) => {
              setForm({ ...form, dst: e.target.value });
            }}
          />
        </label>
        <label className="inline">
          <input
            type="checkbox"
            checked={form.both}
            onChange={(e) => {
              setForm({ ...form, both: e.target.checked });
            }}
          />
          {t('map.both')}
        </label>
        <button type="submit">{t('map.apply')}</button>
      </form>

      {data !== null && (
        <>
          <div className="row map-legend" role="group" aria-label={t('map.col.risk')}>
            {RISKS.map((r) => (
              <label key={r} className={`inline risk-chip risk-${r}`}>
                <input
                  type="checkbox"
                  checked={risks.length === 0 || risks.includes(r)}
                  onChange={() => {
                    toggleRisk(r);
                  }}
                />
                <span className="swatch" aria-hidden="true" />
                {t(`map.risk.${r}`)} (
                {mode === 'flows'
                  ? t('map.rulesCount', { count: (ruleCounts.get(r) ?? 0).toLocaleString() })
                  : (new Map(Object.entries(data.risk_counts)).get(r) ?? 0)}
                )
              </label>
            ))}
            <span className="muted small">{t('map.edges', { count: data.total_edges })}</span>
            <span className="spacer" />
            <div className="segmented" role="group" aria-label={t('map.mode')}>
              {(['flows', 'graph'] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  aria-pressed={mode === m}
                  className={mode === m ? 'active' : ''}
                  onClick={() => {
                    setMode(m === 'flows' ? null : m);
                  }}
                >
                  {t(`map.mode.${m}`)}
                </button>
              ))}
            </div>
            {mode === 'flows' && (
              <div className="segmented" role="group" aria-label={t('map.by')}>
                {(['rules', 'hits'] as const).map((m) => (
                  <button
                    key={m}
                    type="button"
                    aria-pressed={metric === m}
                    className={metric === m ? 'active' : ''}
                    onClick={() => {
                      setBy(m === 'rules' ? null : m);
                    }}
                  >
                    {t(`map.by.${m}`)}
                  </button>
                ))}
              </div>
            )}
          </div>
          {data.truncated && (
            <Alert kind="info">{t('map.truncated', { shown: data.edges.length, total: data.total_edges })}</Alert>
          )}
          {data.edges.length === 0 ? (
            <p className="muted">{t('map.none')}</p>
          ) : (
            <>
            {mode === 'flows' ? (
              <section className="card flow-card">
                <div className="flow-heads muted small" aria-hidden="true">
                  <span>{t('map.sources')}</span>
                  <span>{t('map.destinations')}</span>
                </div>
                <FlowSankey
                  nodes={flowNodes}
                  edges={flowEdges}
                  metric={metric}
                  rtl={dir === 'rtl'}
                  label={t('map.flows')}
                  selected={selected?.kind === 'edge' ? selected.id : null}
                  otherLabel={otherLabel}
                  describe={describe}
                  onSelectEdge={(id) => {
                    setSelected({ kind: 'edge', id });
                  }}
                  onSelectNode={(id) => {
                    setSelected({ kind: 'node', id });
                  }}
                />
              </section>
            ) : null}
            <div className={mode === 'flows' ? 'map-layout flows' : 'map-layout'}>
              {mode === 'flows' ? (
                <FlowInsights
                  edges={data.edges}
                  metric={metric}
                  nodeLabel={(id) => nodeLabel(id)}
                  onSelectEdge={(id) => {
                    setSelected({ kind: 'edge', id });
                  }}
                  onSelectNode={(id) => {
                    setSelected({ kind: 'node', id });
                  }}
                />
              ) : (
              <section className="card map-canvas-card">
                <Graph
                  nodes={graphNodes}
                  edges={graphEdges}
                  rtl={dir === 'rtl'}
                  label={t('map.graph')}
                  columnLabel={columnLabel}
                  onSelectEdge={(id) => {
                    setSelected({ kind: 'edge', id });
                  }}
                  onSelectNode={(id) => {
                    setSelected({ kind: 'node', id });
                  }}
                />
              </section>
              )}
              <section className="card map-side" aria-live="polite">
                {edge !== undefined && snapshotId !== null ? (
                  <EdgeDetail edge={edge} snapshotId={snapshotId} />
                ) : node !== undefined ? (
                  <NodeDetail node={node} />
                ) : (
                  <p className="muted">{t('map.select')}</p>
                )}
              </section>
            </div>
            </>
          )}
          {data.edges.length > 0 && (
            <section className="card">
              <h2>{t('map.table')}</h2>
              <table>
                <SortedTable
                  rows={data.edges}
                  columns={{ from: (e) => nodeLabel(e.src), to: (e) => nodeLabel(e.dst), risk: (e) => RISK_RANK[e.risk], services: (e) => e.services.join(', '), rules: (e) => e.rule_count, hits: (e) => e.hits }}
                  limit={LIST_LIMIT}
                  head={(th) => (
                    <tr>
                      {th('from', t('map.col.from'))}
                      {th('to', t('map.col.to'))}
                      {th('risk', t('map.col.risk'), true)}
                      {th('services', t('map.services'))}
                      {th('rules', t('map.col.rules'), true)}
                      {th('hits', t('map.hits'), true)}
                    </tr>
                  )}
                >
                  {(e) => (
                    <tr key={e.id} className={selected?.id === e.id ? 'selected' : ''}>
                      <td>
                        <button
                          type="button"
                          className="link"
                          onClick={() => {
                            setSelected({ kind: 'edge', id: e.id });
                          }}
                        >
                          <Ltr>{nodeLabel(e.src)}</Ltr>
                        </button>
                      </td>
                      <td>
                        <Ltr>{nodeLabel(e.dst)}</Ltr>
                      </td>
                      <td>
                        <RiskBadge risk={e.risk} />
                      </td>
                      <td className="small">
                        <Ltr>{e.services.slice(0, 3).join(', ')}</Ltr>
                        {e.services.length > 3 && '…'}
                      </td>
                      <td>{e.rule_count}</td>
                      <td>{e.hits.toLocaleString()}</td>
                    </tr>
                  )}
                </SortedTable>
              </table>
            </section>
          )}
        </>
      )}
    </div>
  );
}

function EdgeDetail({ edge, snapshotId }: { edge: MapEdge; snapshotId: number }) {
  const { t } = useI18n();
  const nodeLabel = useNodeLabel();
  const reason = useReasonLabel();
  return (
    <div className="stack">
      <h2>
        <Ltr>{nodeLabel(edge.src)}</Ltr> → <Ltr>{nodeLabel(edge.dst)}</Ltr>
      </h2>
      <div className="rec-facts small">
        <RiskBadge risk={edge.risk} />
        <span>
          <span className="muted">{t('map.hits')}: </span>
          {edge.hits.toLocaleString()}
        </span>
        {edge.min_score !== null && (
          <span>
            <span className="muted">{t('map.minScore')}: </span>
            {edge.min_score}
          </span>
        )}
      </div>
      {edge.reasons.length > 0 && (
        <div>
          <h3>{t('map.why')}</h3>
          <ul className="plain-list small">
            {edge.reasons.map((code) => (
              <li key={code}>{reason(code)}</li>
            ))}
          </ul>
        </div>
      )}
      <div>
        <h3>{t('map.services')}</h3>
        <span className="chips-inline">
          {edge.services.map((s) => (
            <span key={s} className="chip">
              <Ltr>{s}</Ltr>
            </span>
          ))}
        </span>
      </div>
      <div>
        <h3>{t('map.rules', { count: edge.rule_count })}</h3>
        <ul className="plain-list">
          {edge.rules.map((r) => (
            <li key={`${r.policy_id}-${r.id}`}>
              <span className={`swatch-dot risk-${r.risk}`} aria-hidden="true" />{' '}
              <Link
                to={`/rules?snapshot=${String(snapshotId)}&policy=${encodeURIComponent(r.policy_id)}&q=${encodeURIComponent(r.name)}`}
              >
                #{r.index} <Ltr>{r.name}</Ltr>
              </Link>
              {r.score !== null && <span className="muted small"> · {r.score}</span>}
            </li>
          ))}
        </ul>
        {edge.rule_count > edge.rules.length && <div className="muted small">…</div>}
      </div>
    </div>
  );
}

function NodeDetail({ node }: { node: MapNode }) {
  const { t } = useI18n();
  const nodeLabel = useNodeLabel();
  return (
    <div className="stack">
      <h2>
        <Ltr>{nodeLabel(node.id, node.label)}</Ltr>
      </h2>
      {node.tier !== null && <span className={`tier tier-${node.tier.toLowerCase()}`}>{node.tier}</span>}
      {node.user_type !== null && <span className="muted">{node.user_type}</span>}
      {node.networks.length > 0 && (
        <div>
          <h3>{t('map.networks')}</h3>
          <span className="chips-inline">
            {node.networks.map((n) => (
              <span key={n} className="chip">
                <Ltr>{n}</Ltr>
              </span>
            ))}
          </span>
        </div>
      )}
    </div>
  );
}
