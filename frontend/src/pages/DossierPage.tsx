import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

import type { AttackTarget, Dossier, DossierPeer } from '../api/types';
import { Alert, Ltr } from '../components/common';
import { DossierDiagram } from '../components/DossierDiagram';
import type { Side } from '../components/DossierDiagram';
import { SnapshotPicker } from '../components/inventory';
import { PolicyPicker, ScopeNote, usePolicyScope } from '../components/policyScope';
import { useApi, useQueryParam, useSetQueryParams, useSnapshotSelection } from '../hooks';
import { isMessageKey, useI18n } from '../i18n/I18nProvider';

const SHOWN = 25; // peers drawn per side before "show all"
const COMPONENTS_SHOWN = 5;
const TIERS = ['CORE', 'GOLD', 'SILVER', 'BRONZE', 'USERS'];
const RISKS = ['all', 'yellow', 'red'] as const;
type RiskFilter = (typeof RISKS)[number];
const rank = (r: string): number => (r === 'red' ? 2 : r === 'yellow' ? 1 : 0);
const pick = <T,>(side: Side, inbound: T, outbound: T): T => (side === 'inbound' ? inbound : outbound);

/** System dossier: one system at the centre, who reaches it and what it reaches. */
export function DossierPage() {
  const { t, tError, dir } = useI18n();
  const { snapshots, snapshotId, setSnapshotId, error: snapError } = useSnapshotSelection();
  const [system] = useQueryParam('system');
  const [viewParam] = useQueryParam('view');
  const [riskParam] = useQueryParam('risk');
  const [broadParam] = useQueryParam('broad');
  const setParams = useSetQueryParams();
  const [filter, setFilter] = useState('');
  const [all, setAll] = useState<Record<Side, boolean>>({ inbound: false, outbound: false });
  const [selected, setSelected] = useState<{ side: Side; key: string } | null>(null);
  const [systemFilter, setSystemFilter] = useState('');
  const [showComponents, setShowComponents] = useState(false);
  const scope = usePolicyScope(snapshotId);
  const narrow = useNarrow();
  const view = viewParam === 'table' || viewParam === 'diagram' ? viewParam : narrow ? 'table' : 'diagram';
  const risk: RiskFilter = RISKS.find((r) => r === riskParam) ?? 'all';
  const hideBroad = broadParam === 'hide';

  const base = snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}`;
  const targets = useApi<AttackTarget[]>(base === null ? null : `${base}/attack-surface/targets`);
  const query = new URLSearchParams();
  if (system !== null) query.set('system', system);
  if (scope.policy !== null) query.set('policy', scope.policy);
  const dossier = useApi<Dossier>(base !== null && system !== null ? `${base}/dossier?${query.toString()}` : null);
  const data = dossier.data !== null && dossier.data.system.id === system ? dossier.data : null;

  const peerName = (p: DossierPeer): string => {
    if (p.kind === 'any') return t('dsr.any');
    if (p.kind === 'network') return t('dsr.zoneNetworks');
    if (p.kind === 'default') return t('dsr.defaultAction', { policy: p.label });
    return p.label;
  };
  const peerSub = (p: DossierPeer): string => {
    if (p.kind === 'default') return t('dsr.defaultSub');
    if (p.kind === 'any') return t('dsr.anySub');
    const values = p.values.slice(0, 2).join(', ');
    const more = p.values.length > 2 ? ` ${t('dsr.more', { count: p.values.length - 2 })}` : '';
    const kind = p.kind === 'object' ? t('dsr.notAsset') : p.tier ?? '';
    return [kind, values + more].filter((s) => s !== '').join(' · ');
  };

  const visible = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    const keep = (p: DossierPeer) =>
      (!hideBroad || p.specific > 0) &&
      (risk === 'all' || rank(p.risk) >= rank(risk)) &&
      (needle === '' ||
        [p.label, ...p.values, ...p.services, ...p.apps].some((v) => v.toLowerCase().includes(needle)));
    return {
      inbound: (data?.inbound ?? []).filter(keep),
      outbound: (data?.outbound ?? []).filter(keep),
    };
  }, [data, filter, hideBroad, risk]);
  const drawn = {
    inbound: all.inbound ? visible.inbound : visible.inbound.slice(0, SHOWN),
    outbound: all.outbound ? visible.outbound : visible.outbound.slice(0, SHOWN),
  };
  const selectedPeer =
    selected === null ? undefined : (data === null ? [] : pick(selected.side, data.inbound, data.outbound)).find((p) => p.key === selected.key);

  function choose(id: string | null) {
    setSelected(null);
    setAll({ inbound: false, outbound: false });
    setShowComponents(false);
    setParams({ system: id });
  }

  const byTier = new Map<string, AttackTarget[]>();
  const needle = systemFilter.trim().toLowerCase();
  for (const target of targets.data ?? []) {
    if (needle !== '' && !target.label.toLowerCase().includes(needle) && !target.networks.some((n) => n.includes(needle)))
      continue;
    byTier.set(target.tier, [...(byTier.get(target.tier) ?? []), target]);
  }
  const tiers = [...TIERS.filter((tier) => byTier.has(tier)), ...[...byTier.keys()].filter((k) => !TIERS.includes(k))];
  const error = snapError ?? targets.error ?? dossier.error;
  const kindKey = data === null ? null : `dsr.kind.${data.system.kind}`;

  return (
    <div className="stack">
      <div className="row spread">
        <h1>{t('dsr.title')}</h1>
        <div className="row page-filters">
          <SnapshotPicker snapshots={snapshots} value={snapshotId} onChange={setSnapshotId} />
          <PolicyPicker scope={scope} />
        </div>
      </div>
      <p className="muted">{t('dsr.help')}</p>
      <ScopeNote scope={scope} />
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      {snapshotId === null && snapError === null && <Alert kind="info">{t('snap.none')}</Alert>}

      {snapshotId !== null && (
        <section className="card dsr-picker">
          <label className="inline-field">
            {t('dsr.system')}
            <select
              value={system ?? ''}
              onChange={(e) => {
                choose(e.target.value === '' ? null : e.target.value);
              }}
            >
              <option value="">{t('dsr.choose')}</option>
              {tiers.map((tier) => (
                <optgroup key={tier} label={tier}>
                  {(byTier.get(tier) ?? []).map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.label}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
          </label>
          {system === null && (
            <>
              <input
                type="search"
                dir="auto"
                maxLength={64}
                className="dsr-system-search"
                aria-label={t('dsr.findSystem')}
                placeholder={t('dsr.findSystem')}
                value={systemFilter}
                onChange={(e) => {
                  setSystemFilter(e.target.value);
                }}
              />
              {targets.data !== null && targets.data.length === 0 && <Alert kind="info">{t('dsr.noAssets')}</Alert>}
              <div className="dsr-systems">
                {tiers.map((tier) => (
                  <div key={tier} className="dsr-tier-group">
                    <div className={`dsr-tier-title tier-${tier.toLowerCase()}`}>{tier}</div>
                    <div className="dsr-chips">
                      {(byTier.get(tier) ?? []).map((s) => (
                        <button
                          key={s.id}
                          type="button"
                          className={`dsr-chip tier-${tier.toLowerCase()}`}
                          onClick={() => {
                            choose(s.id);
                          }}
                        >
                          {s.label}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </section>
      )}

      {system !== null && dossier.loading && data === null && <p className="muted">{t('common.loading')}</p>}

      {data !== null && (
        <>
          <section className="card dsr-header">
            <div className="dsr-header-main">
              <div className="row">
                <h2>{data.system.name}</h2>
                <span className={`badge tier-${data.system.tier.toLowerCase()}`}>{data.system.tier}</span>
                {kindKey !== null && isMessageKey(kindKey) && <span className="muted">{t(kindKey)}</span>}
              </div>
              {data.system.description !== '' && <p>{data.system.description}</p>}
              {data.system.owner !== '' && <p className="muted small">{t('dsr.owner', { owner: data.system.owner })}</p>}
              <div className="row dsr-links">
                <Link to={`/attack?snapshot=${String(snapshotId)}&system=${encodeURIComponent(data.system.id)}`}>
                  {t('dsr.openAttack')}
                </Link>
                <Link to="/assets">{t('dsr.openAssets')}</Link>
              </div>
            </div>
            <div className="dsr-stats">
              <Stat label={t('dsr.statInbound')} value={data.summary.inbound_peers} sub={t('dsr.rules', { count: data.summary.inbound_rules })} />
              <Stat label={t('dsr.statOutbound')} value={data.summary.outbound_peers} sub={t('dsr.rules', { count: data.summary.outbound_rules })} />
              <Stat label={t('dsr.statInternal')} value={data.summary.internal_rules} sub={t('dsr.internalSub')} />
            </div>
            <table className="dsr-components">
              <thead>
                <tr>
                  <th>{t('dsr.col.component')}</th>
                  <th>{t('dsr.col.address')}</th>
                  <th>{t('dsr.col.role')}</th>
                  <th>{t('dsr.col.ports')}</th>
                </tr>
              </thead>
              <tbody>
                {(showComponents ? data.system.components : data.system.components.slice(0, COMPONENTS_SHOWN)).map((c) => (
                  <tr key={`${c.name}:${c.network}`}>
                    <td>{c.name}</td>
                    <td>
                      <Ltr>{c.network}</Ltr>
                    </td>
                    <td>{c.role}</td>
                    <td>
                      <Ltr>{c.ports}</Ltr>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {data.system.components.length > COMPONENTS_SHOWN && (
              <button
                type="button"
                className="link dsr-components-more"
                onClick={() => {
                  setShowComponents((v) => !v);
                }}
              >
                {showComponents
                  ? t('dsr.componentsFewer')
                  : t('dsr.componentsAll', { count: data.system.components.length })}
              </button>
            )}
          </section>

          {data.summary.truncated && <Alert kind="info">{t('dsr.truncated')}</Alert>}

          <div className="row dsr-toolbar">
            <div className="segmented" role="group" aria-label={t('dsr.view')}>
              {(['diagram', 'table'] as const).map((v) => (
                <button
                  key={v}
                  type="button"
                  className={view === v ? 'active' : ''}
                  aria-pressed={view === v}
                  onClick={() => {
                    setParams({ view: v });
                  }}
                >
                  {t(v === 'diagram' ? 'dsr.viewDiagram' : 'dsr.viewTable')}
                </button>
              ))}
            </div>
            <div className="segmented" role="group" aria-label={t('dsr.risk')}>
              {RISKS.map((r) => (
                <button
                  key={r}
                  type="button"
                  className={risk === r ? 'active' : ''}
                  aria-pressed={risk === r}
                  onClick={() => {
                    setSelected(null);
                    setParams({ risk: r === 'all' ? null : r });
                  }}
                >
                  {t(r === 'all' ? 'dsr.riskAll' : r === 'yellow' ? 'dsr.riskYellow' : 'dsr.riskRed')}
                </button>
              ))}
            </div>
            <label className="inline">
              <input
                type="checkbox"
                checked={hideBroad}
                onChange={(e) => {
                  setSelected(null);
                  setParams({ broad: e.target.checked ? 'hide' : null });
                }}
              />
              {t('dsr.hideBroad')}
            </label>
            <input
              type="search"
              dir="auto"
              maxLength={64}
              className="grow"
              aria-label={t('dsr.filter')}
              placeholder={t('dsr.filter')}
              value={filter}
              onChange={(e) => {
                setSelected(null);
                setFilter(e.target.value);
              }}
            />
          </div>

          {visible.inbound.length === 0 && visible.outbound.length === 0 ? (
            <Alert kind="info">{t(data.inbound.length + data.outbound.length === 0 ? 'dsr.noFlows' : 'dsr.noMatch')}</Alert>
          ) : view === 'diagram' ? (
            <div className="dsr-layout">
              <section className="card dsr-canvas">
                <DossierDiagram
                  dossier={data}
                  inbound={drawn.inbound}
                  outbound={drawn.outbound}
                  selected={selected}
                  onSelect={(side, key) => {
                    setSelected(selected?.side === side && selected.key === key ? null : { side, key });
                  }}
                  rtl={dir === 'rtl'}
                  labels={{
                    inbound: t('dsr.inbound', { count: visible.inbound.length }),
                    outbound: t('dsr.outbound', { count: visible.outbound.length }),
                    peerName,
                    peerSub,
                    more: (count) => t('dsr.more', { count }),
                  }}
                />
                <div className="row dsr-more">
                  {(['inbound', 'outbound'] as const).map(
                    (side) =>
                      pick(side, visible.inbound, visible.outbound).length > SHOWN && (
                        <button
                          key={side}
                          type="button"
                          className="secondary"
                          onClick={() => {
                            setAll((prev) =>
                              side === 'inbound'
                                ? { ...prev, inbound: !prev.inbound }
                                : { ...prev, outbound: !prev.outbound },
                            );
                          }}
                        >
                          {pick(side, all.inbound, all.outbound)
                            ? t('dsr.showFewer', { count: SHOWN })
                            : t(side === 'inbound' ? 'dsr.showAllInbound' : 'dsr.showAllOutbound', {
                                count: pick(side, visible.inbound, visible.outbound).length,
                              })}
                        </button>
                      ),
                  )}
                </div>
                <Legend />
              </section>
              <PeerPanel
                peer={selectedPeer}
                side={selected?.side ?? null}
                name={selectedPeer === undefined ? '' : peerName(selectedPeer)}
                snapshotId={snapshotId}
                onClose={() => {
                  setSelected(null);
                }}
              />
            </div>
          ) : (
            <div className="stack">
              {(['inbound', 'outbound'] as const).map((side) => (
                <PeerTable
                  key={side}
                  side={side}
                  peers={pick(side, visible.inbound, visible.outbound)}
                  name={peerName}
                  onOpen={(key) => {
                    setSelected({ side, key });
                    setParams({ view: 'diagram' });
                  }}
                />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

/** True on a phone-width screen (follows resizes). */
function useNarrow(): boolean {
  const media = useMemo(
    () => (typeof window.matchMedia === 'function' ? window.matchMedia('(max-width: 700px)') : null),
    [],
  );
  const [narrow, setNarrow] = useState(media?.matches ?? false);
  useEffect(() => {
    if (media === null) return;
    const update = () => {
      setNarrow(media.matches);
    };
    media.addEventListener('change', update);
    return () => {
      media.removeEventListener('change', update);
    };
  }, [media]);
  return narrow;
}

function Stat({ label, value, sub }: { label: string; value: number; sub: string }) {
  return (
    <div className="dsr-stat">
      <div className="dsr-stat-value">{value.toLocaleString()}</div>
      <div className="dsr-stat-label">{label}</div>
      <div className="muted small">{sub}</div>
    </div>
  );
}

function Legend() {
  const { t } = useI18n();
  return (
    <ul className="dsr-legend" aria-label={t('dsr.legend')}>
      <li>
        <span className="dsr-swatch risk-green" /> {t('dsr.legendGreen')}
      </li>
      <li>
        <span className="dsr-swatch risk-yellow" /> {t('dsr.legendYellow')}
      </li>
      <li>
        <span className="dsr-swatch risk-red" /> {t('dsr.legendRed')}
      </li>
      <li>
        <span className="dsr-swatch broad" /> {t('dsr.legendBroad')}
      </li>
      <li>
        <span className="dsr-box kind-object" /> {t('dsr.legendObject')}
      </li>
    </ul>
  );
}

function PeerPanel({
  peer,
  side,
  name,
  snapshotId,
  onClose,
}: {
  peer: DossierPeer | undefined;
  side: Side | null;
  name: string;
  snapshotId: number | null;
  onClose: () => void;
}) {
  const { t } = useI18n();
  if (peer === undefined || side === null) {
    return (
      <aside className="card dsr-panel muted" aria-live="polite">
        {t('dsr.pickPeer')}
      </aside>
    );
  }
  return (
    <aside className="card dsr-panel" aria-live="polite">
      <div className="row spread">
        <h3>{name}</h3>
        <button type="button" className="secondary small" onClick={onClose} aria-label={t('dash.close', { name })}>
          ×
        </button>
      </div>
      <p className="muted small">
        {t(side === 'inbound' ? 'dsr.panelInbound' : 'dsr.panelOutbound')} · {t(`dsr.peerKind.${peer.kind}`)}
      </p>
      {peer.values.length > 0 && (
        <Field label={t('dsr.addresses')}>
          {peer.values.map((v) => (
            <span key={v} className="chip">
              <Ltr>{v}</Ltr>
            </span>
          ))}
        </Field>
      )}
      <Field label={t('dsr.services')}>
        {[...peer.services, ...peer.apps].map((s) => (
          <span key={s} className="chip dsr-svc">
            <Ltr>{s}</Ltr>
          </span>
        ))}
      </Field>
      {peer.targets.length > 0 && (
        <Field label={t(side === 'inbound' ? 'dsr.reachesComponents' : 'dsr.fromComponents')}>
          {peer.targets.map((c) => (
            <span key={c} className="chip">
              {c}
            </span>
          ))}
        </Field>
      )}
      {peer.conditions.length > 0 && (
        <Field label={t('dsr.onlyFor')}>
          {peer.conditions.map((c) => (
            <span key={`${c.field}:${c.name}`} className="chip">
              {c.name}
            </span>
          ))}
        </Field>
      )}
      <ul className="dsr-flags">
        {peer.broad > 0 && <li className="warn">{t('dsr.flagBroad', { count: peer.broad })}</li>}
        {peer.rule_count - peer.inspected > 0 && (
          <li>{t('dsr.flagUninspected', { count: peer.rule_count - peer.inspected })}</li>
        )}
        <li>{peer.hits === null ? t('dsr.hitsUnknown') : t('dsr.hits', { count: peer.hits })}</li>
      </ul>
      <h4>{t('dsr.rulesTitle', { count: peer.rule_count })}</h4>
      <ul className="dsr-rules">
        {peer.rules.map((r) => (
          <li key={`${r.policy_id}:${r.id}`} className={`risk-${r.risk}`}>
            {r.default ? (
              <span>{t('dsr.defaultRule', { policy: r.policy })}</span>
            ) : (
              <Link
                to={`/rules?snapshot=${String(snapshotId)}&policy=${encodeURIComponent(r.policy_id)}&q=${encodeURIComponent(r.name)}`}
              >
                #{r.index} <Ltr>{r.name}</Ltr>
              </Link>
            )}
            <div className="muted small">
              {r.policy} · {r.action}
              {r.broad && ` · ${t('dsr.broadTag')}`}
              {!r.inspected && ` · ${t('dsr.noIps')}`}
              {r.partial && ` · ${t('dsr.partialTag')}`}
              {r.hits !== null && ` · ${t('dsr.hits', { count: r.hits })}`}
            </div>
            <div className="small">
              <Ltr>{r.services.join(' · ')}</Ltr>
            </div>
          </li>
        ))}
      </ul>
      {peer.rule_count > peer.rules.length && (
        <p className="muted small">{t('dsr.rulesSample', { shown: peer.rules.length, count: peer.rule_count })}</p>
      )}
    </aside>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="dsr-field">
      <div className="dsr-field-label">{label}</div>
      <div className="chips-inline">{children}</div>
    </div>
  );
}

function PeerTable({
  side,
  peers,
  name,
  onOpen,
}: {
  side: Side;
  peers: DossierPeer[];
  name: (p: DossierPeer) => string;
  onOpen: (key: string) => void;
}) {
  const { t } = useI18n();
  return (
    <section className="card dsr-peers">
      <h3>{t(side === 'inbound' ? 'dsr.inbound' : 'dsr.outbound', { count: peers.length })}</h3>
      <table>
        <thead>
          <tr>
            <th>{t('dsr.col.peer')}</th>
            <th>{t('dsr.col.kind')}</th>
            <th>{t('dsr.addresses')}</th>
            <th>{t('dsr.services')}</th>
            <th>{t('dsr.col.rules')}</th>
            <th>{t('dsr.col.hits')}</th>
          </tr>
        </thead>
        <tbody>
          {peers.map((p) => (
            <tr key={p.key} className={`dsr-row risk-${p.risk}`}>
              <td>
                <button
                  type="button"
                  className="link"
                  onClick={() => {
                    onOpen(p.key);
                  }}
                >
                  {name(p)}
                </button>
              </td>
              <td>{t(`dsr.peerKind.${p.kind}`)}</td>
              <td>
                <Ltr>{p.values.slice(0, 3).join(', ')}</Ltr>
              </td>
              <td>
                <Ltr>{[...p.services, ...p.apps].slice(0, 6).join(' · ')}</Ltr>
              </td>
              <td>
                {p.rule_count}
                {p.specific === 0 && <span className="badge dsr-broad-badge">{t('dsr.broadTag')}</span>}
              </td>
              <td>{p.hits ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
