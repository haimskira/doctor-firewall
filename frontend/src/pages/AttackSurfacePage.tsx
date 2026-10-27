import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import type { AttackEdge, AttackNode, AttackRule, AttackSurface, AttackTarget, Cluster } from '../api/types';
import { AttackMap } from '../components/AttackMap';
import type { Highlight } from '../components/AttackMap';
import { Alert, Ltr } from '../components/common';
import { SnapshotPicker } from '../components/inventory';
import { useApi, useQueryParam, useSnapshotSelection } from '../hooks';
import { isMessageKey, useI18n } from '../i18n/I18nProvider';

const DEPTHS = ['1', '2', '3', '4'] as const;
const PATHS_SHOWN = 40;

type Selection = { kind: 'path'; index: number } | { kind: 'node'; id: string } | { kind: 'edge'; id: string } | null;

/** Attack surface: every way the rulebase lets traffic reach a target, or a blast radius. */
export function AttackSurfacePage() {
  const { t, tError, dir } = useI18n();
  const arrow = dir === 'rtl' ? ' ← ' : ' → ';
  const hops = (n: number) => (n === 1 ? t('atk.oneHop') : t('atk.hops', { count: n }));
  const { snapshots, snapshotId, setSnapshotId, error: snapError } = useSnapshotSelection();
  const [modeParam, setMode] = useQueryParam('mode');
  const [system, setSystem] = useQueryParam('system');
  const [address, setAddress] = useQueryParam('address');
  const [depthParam, setDepth] = useQueryParam('depth');
  const [cluster, setCluster] = useQueryParam('cluster');
  const [draft, setDraft] = useState(address ?? '');
  const [selection, setSelection] = useState<Selection>(null);
  const mode = modeParam === 'from' ? 'from' : 'to';
  const depth = DEPTHS.find((d) => d === depthParam) ?? '3';

  const base = snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}`;
  const targets = useApi<AttackTarget[]>(base === null ? null : `${base}/attack-surface/targets`);
  const clusters = useApi<Cluster[]>(base === null ? null : `${base}/clusters`);
  const query = new URLSearchParams({ mode, depth });
  if (system !== null) query.set('system', system);
  else if (address !== null) query.set('address', address);
  if (cluster !== null) query.set('cluster', cluster);
  const ready = base !== null && (system !== null || address !== null);
  const surface = useApi<AttackSurface>(ready ? `${base}/attack-surface?${query.toString()}` : null);
  const data = surface.data;

  const named = useMemo(() => {
    if (data === null) return null;
    const label = (n: AttackNode) =>
      n.kind === 'anywhere' ? t('atk.anywhere') : n.kind === 'unclassified' ? t('atk.unclassified') : n.label;
    return { ...data, nodes: data.nodes.map((n) => ({ ...n, label: label(n) })) };
  }, [data, t]);
  const nodes = useMemo(() => new Map((named?.nodes ?? []).map((n) => [n.id, n])), [named]);
  const nodeLabel = (id: string) => nodes.get(id)?.label ?? id;

  const highlight = useMemo<Highlight | null>(() => {
    if (named === null || selection === null) return null;
    if (selection.kind === 'path') {
      const path = named.paths.at(selection.index);
      if (path === undefined) return null;
      const edges = new Set<string>();
      path.steps.slice(1).forEach((step, i) => {
        for (const s of path.steps.at(i)?.nodes ?? []) for (const d of step.nodes) edges.add(`${s}->${d}`);
      });
      return { nodes: new Set(path.steps.flatMap((s) => s.nodes)), edges };
    }
    if (selection.kind === 'node') {
      const touching = named.edges.filter((e) => e.src === selection.id || e.dst === selection.id);
      return {
        nodes: new Set([selection.id, ...touching.flatMap((e) => [e.src, e.dst])]),
        edges: new Set(touching.map((e) => e.id)),
      };
    }
    const edge = named.edges.find((e) => e.id === selection.id);
    return edge === undefined ? null : { nodes: new Set([edge.src, edge.dst]), edges: new Set([edge.id]) };
  }, [named, selection]);

  function chooseSystem(value: string) {
    setSelection(null);
    setAddress(null);
    setSystem(value === '' ? null : value);
  }

  function submitAddress() {
    setSelection(null);
    setSystem(null);
    setAddress(draft.trim() === '' ? null : draft.trim());
  }

  const byTier = new Map<string, AttackTarget[]>();
  for (const target of targets.data ?? []) byTier.set(target.tier, [...(byTier.get(target.tier) ?? []), target]);
  const error = snapError ?? targets.error ?? surface.error;
  const selectedEdge = selection?.kind === 'edge' ? named?.edges.find((e) => e.id === selection.id) : undefined;
  const selectedNode = selection?.kind === 'node' ? nodes.get(selection.id) : undefined;

  return (
    <div className="stack">
      <div className="row spread">
        <h1>{t('atk.title')}</h1>
        <SnapshotPicker snapshots={snapshots} value={snapshotId} onChange={setSnapshotId} />
      </div>
      <p className="muted">{t(mode === 'to' ? 'atk.helpTo' : 'atk.helpFrom')}</p>
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      {snapshotId === null && snapError === null && <Alert kind="info">{t('snap.none')}</Alert>}
      {snapshotId !== null && (
        <section className="card atk-controls" aria-label={t('atk.controls')}>
          <div className="segmented" role="group" aria-label={t('atk.mode')}>
            {(['to', 'from'] as const).map((m) => (
              <button
                key={m}
                type="button"
                className={mode === m ? '' : 'secondary'}
                aria-pressed={mode === m}
                onClick={() => {
                  setSelection(null);
                  setMode(m === 'to' ? null : m);
                }}
              >
                {t(m === 'to' ? 'atk.modeTo' : 'atk.modeFrom')}
              </button>
            ))}
          </div>
          <label className="inline-field">
            {t(mode === 'to' ? 'atk.target' : 'atk.source')}
            <select
              value={system ?? ''}
              onChange={(e) => {
                chooseSystem(e.target.value);
              }}
            >
              <option value="">{t('atk.pickSystem')}</option>
              {[...byTier.entries()].map(([tier, list]) => (
                <optgroup key={tier} label={tier}>
                  {list.map((target) => (
                    <option key={target.id} value={target.id}>
                      {target.label}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
          </label>
          <form
            className="inline-field"
            onSubmit={(e) => {
              e.preventDefault();
              submitAddress();
            }}
          >
            <label className="inline-field">
              {t('atk.orAddress')}
              <input
                type="search"
                dir="ltr"
                maxLength={96}
                placeholder="10.20.0.0/24"
                value={draft}
                onChange={(e) => {
                  setDraft(e.target.value);
                }}
              />
            </label>
            <button type="submit" className="secondary">
              {t('atk.analyse')}
            </button>
          </form>
          <label className="inline-field">
            {t('atk.depth')}
            <select
              value={depth}
              onChange={(e) => {
                setSelection(null);
                setDepth(e.target.value === '3' ? null : e.target.value);
              }}
            >
              {DEPTHS.map((d) => (
                <option key={d} value={d}>
                  {hops(Number(d))}
                </option>
              ))}
            </select>
          </label>
          <label className="inline-field">
            {t('rules.cluster')}
            <select
              value={cluster ?? ''}
              onChange={(e) => {
                setSelection(null);
                setCluster(e.target.value === '' ? null : e.target.value);
              }}
            >
              <option value="">{t('atk.allClusters')}</option>
              {(clusters.data ?? []).map((c) => (
                <option key={c.fmc_id} value={c.fmc_id}>
                  {c.name}
                </option>
              ))}
            </select>
          </label>
        </section>
      )}
      {snapshotId !== null && !ready && <Alert kind="info">{t('atk.pickFirst')}</Alert>}
      {ready && surface.loading && <p className="muted">{t('atk.analysing')}</p>}
      {named !== null && snapshotId !== null && (
        <>
          <Summary data={named} hops={hops} />
          {named.paths.length === 0 ? (
            <Alert kind="success">{t(mode === 'to' ? 'atk.noPathsTo' : 'atk.noPathsFrom')}</Alert>
          ) : (
            <div className="map-layout">
              <section className="card">
                <AttackMap
                  data={named}
                  highlight={highlight}
                  label={t('atk.mapLabel')}
                  ringLabel={hops}
                  onNode={(n) => {
                    setSelection(selection?.kind === 'node' && selection.id === n.id ? null : { kind: 'node', id: n.id });
                  }}
                  onEdge={(e) => {
                    setSelection(selection?.kind === 'edge' && selection.id === e.id ? null : { kind: 'edge', id: e.id });
                  }}
                />
                <Legend />
              </section>
              <section className="card stack atk-side" aria-label={t('atk.paths')}>
                {selectedNode !== undefined && <NodePanel node={selectedNode} />}
                {selectedEdge !== undefined && (
                  <EdgePanel edge={selectedEdge} from={nodeLabel(selectedEdge.src)} to={nodeLabel(selectedEdge.dst)} arrow={arrow} snapshotId={snapshotId} />
                )}
                <h2>{t('atk.paths')}</h2>
                <ol className="atk-paths">
                  {named.paths.slice(0, PATHS_SHOWN).map((path, i) => {
                    const open = selection?.kind === 'path' && selection.index === i;
                    return (
                      <li key={path.steps.map((s) => s.nodes.join('+')).join('>')} className={open ? 'open' : ''}>
                        <button
                          type="button"
                          className="link atk-path"
                          aria-expanded={open}
                          onClick={() => {
                            setSelection(open ? null : { kind: 'path', index: i });
                          }}
                        >
                          <span className={`score score-${path.score >= 90 ? 'bad' : path.score >= 60 ? 'warn' : 'good'}`}>{path.score}</span>{' '}
                          {path.steps.map((s, k) => (
                            <span key={String(k)}>
                              {k > 0 && arrow}
                              <bdi>{s.nodes.map(nodeLabel).join(' / ')}</bdi>
                            </span>
                          ))}
                        </button>
                        <div className="atk-reasons">
                          {path.reasons.map((r) => {
                            const key = `atk.reason.${r}`;
                            return (
                              <span key={r} className={`chip small reason-${r}`}>
                                {isMessageKey(key) ? t(key) : r}
                              </span>
                            );
                          })}
                        </div>
                        {open && (
                          <ol className="atk-hops">
                            {path.hops.map((hop, h) => (
                              <li key={String(h)}>
                                <div>
                                  <bdi>{path.steps.at(h)?.nodes.map(nodeLabel).join(' / ')}</bdi>
                                  {arrow}
                                  <bdi>{path.steps.at(h + 1)?.nodes.map(nodeLabel).join(' / ')}</bdi>
                                </div>
                                <div className="muted small">
                                  <Ltr>{(path.steps.at(h + 1)?.networks ?? []).join(', ')}</Ltr>
                                </div>
                                <Services services={hop.services} apps={hop.apps} />
                                <RuleList rules={hop.rules} total={hop.rule_count} snapshotId={snapshotId} />
                              </li>
                            ))}
                          </ol>
                        )}
                      </li>
                    );
                  })}
                </ol>
                {named.paths.length > PATHS_SHOWN && <p className="muted small">{t('atk.morePaths', { count: named.paths.length - PATHS_SHOWN })}</p>}
              </section>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function Summary({ data, hops }: { data: AttackSurface; hops: (n: number) => string }) {
  const { t } = useI18n();
  const s = data.summary;
  return (
    <section className="card atk-summary" aria-label={t('atk.summary')}>
      <div className="atk-kpis">
        <Kpi label={t('atk.kpi.paths')} value={String(s.paths)} />
        <Kpi label={t(data.mode === 'to' ? 'atk.kpi.entries' : 'atk.kpi.reached')} value={String(data.mode === 'to' ? s.entry_points : s.reached)} />
        <Kpi label={t('atk.kpi.shortest')} value={s.shortest === null ? '—' : hops(s.shortest)} />
        <Kpi
          label={t(data.mode === 'to' ? 'atk.kpi.anywhereTo' : 'atk.kpi.anywhereFrom')}
          value={s.anywhere ? t('common.yes') : t('common.no')}
          tone={s.anywhere ? 'bad' : 'good'}
        />
      </div>
      {s.services.length > 0 && (
        <div className="row">
          <span className="muted">{t(data.mode === 'to' ? 'atk.exposed' : 'atk.usedServices')}</span>
          {s.services.map((svc) => (
            <span key={svc} className="chip">
              <Ltr>{svc}</Ltr>
            </span>
          ))}
        </div>
      )}
      <p className="muted small">
        {t('atk.originNets')}: <Ltr>{data.origin.networks.join(', ')}</Ltr>
      </p>
      {s.truncated && <Alert kind="info">{t('atk.truncated')}</Alert>}
    </section>
  );
}

function Kpi({ label, value, tone }: { label: string; value: string; tone?: 'good' | 'bad' }) {
  return (
    <div className={`atk-kpi${tone === undefined ? '' : ` tone-${tone}`}`}>
      <div className="atk-kpi-value">{value}</div>
      <div className="atk-kpi-label">{label}</div>
    </div>
  );
}

function Services({ services, apps }: { services: string[]; apps: string[] }) {
  const { t } = useI18n();
  return (
    <div className="row small">
      {services.map((svc) => (
        <span key={svc} className={`chip${svc === 'any' ? ' chip-any' : ''}`}>
          <Ltr>{svc === 'any' ? t('atk.anyService') : svc}</Ltr>
        </span>
      ))}
      {apps.map((app) => (
        <span key={app} className="chip">
          <bdi>{app}</bdi>
        </span>
      ))}
    </div>
  );
}

function RuleList({ rules, total, snapshotId }: { rules: AttackRule[]; total: number; snapshotId: number }) {
  const { t } = useI18n();
  return (
    <ul className="plain-list small atk-rules">
      {rules.map((r) => (
        <li key={r.id}>
          {r.default ? (
            <span>
              <bdi>{r.policy}</bdi>: {t('atk.defaultAction', { action: r.action })}
            </span>
          ) : (
            <Link to={`/rules?snapshot=${String(snapshotId)}&policy=${encodeURIComponent(r.policy_id)}&q=${encodeURIComponent(r.name)}`}>
              <bdi>{`#${String(r.index)} ${r.name}`}</bdi>
            </Link>
          )}{' '}
          <span className="muted">· {r.inspected ? t('atk.inspected') : t('atk.notInspected')}</span>
          {r.partial && <span className="muted"> · {t('atk.partial')}</span>}
          {(r.conditions ?? []).length > 0 && (
            <span className="atk-conditions" title={t('atk.conditionsHint')}>
              {' · '}
              {t('atk.conditional')}:{' '}
              {(r.conditions ?? []).map((c) => (
                <span key={`${c.field}-${c.name}`} className="chip small">
                  <FieldLabel field={c.field} />: <bdi>{c.name}</bdi>
                </span>
              ))}
            </span>
          )}
        </li>
      ))}
      {total > rules.length && <li className="muted">{t('atk.moreRules', { count: total - rules.length })}</li>}
    </ul>
  );
}

function NodePanel({ node }: { node: AttackNode }) {
  const { t } = useI18n();
  return (
    <div className="atk-detail">
      <h2>
        <bdi>{node.label}</bdi> {node.tier !== null && <span className={`tier tier-${node.tier.toLowerCase()}`}>{node.tier}</span>}
      </h2>
      <p className="muted small">{node.depth === 0 ? t('atk.isOrigin') : node.depth === 1 ? t('atk.oneHopAway') : t('atk.hopsAway', { count: node.depth })}</p>
      <p className="small">
        <Ltr>{node.networks.join(', ')}</Ltr>
      </p>
    </div>
  );
}

function EdgePanel({ edge, from, to, arrow, snapshotId }: { edge: AttackEdge; from: string; to: string; arrow: string; snapshotId: number }) {
  const { t } = useI18n();
  return (
    <div className="atk-detail">
      <h2>
        <bdi>{from}</bdi>
        {arrow}
        <bdi>{to}</bdi>
      </h2>
      <span className={`badge risk-badge risk-${edge.risk}`}>{t(`map.risk.${edge.risk}`)}</span>
      <Services services={edge.services} apps={edge.apps} />
      <RuleList rules={edge.rules} total={edge.rule_count} snapshotId={snapshotId} />
    </div>
  );
}

function Legend() {
  const { t } = useI18n();
  return (
    <div className="row small muted atk-legend">
      {(['red', 'yellow', 'green'] as const).map((r) => (
        <span key={r}>
          <span className={`swatch-dot risk-${r}`} /> {t(`map.risk.${r}`)}
        </span>
      ))}
      <span>{t('atk.legendArrows')}</span>
    </div>
  );
}

function FieldLabel({ field }: { field: string }) {
  const { t } = useI18n();
  const key = `field.${field}`;
  return <>{isMessageKey(key) ? t(key) : field}</>;
}
