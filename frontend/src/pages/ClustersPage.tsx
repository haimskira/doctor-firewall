import { useState } from 'react';
import type { SyntheticEvent } from 'react';
import { Link } from 'react-router-dom';

import { api, errorCode } from '../api/client';
import type { Cluster, ClusterLimits, ClusterNetwork, RouteLookup } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { Alert, Ltr } from '../components/common';
import { SnapshotPicker } from '../components/inventory';
import { useApi, useQueryParam, useSnapshotSelection } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';

export function ClustersPage() {
  const { t, tError } = useI18n();
  const { snapshots, snapshotId, setSnapshotId, error } = useSnapshotSelection();
  const [clusterId, setClusterId] = useQueryParam('cluster');
  const clusters = useApi<Cluster[]>(snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}/clusters`);
  const network = useApi<ClusterNetwork>(
    snapshotId === null || clusterId === null
      ? null
      : `/api/snapshots/${String(snapshotId)}/clusters/${encodeURIComponent(clusterId)}/network`,
  );

  return (
    <div className="stack">
      <div className="row spread">
        <h1>{t('clusters.title')}</h1>
        <SnapshotPicker snapshots={snapshots} value={snapshotId} onChange={setSnapshotId} />
      </div>
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      {snapshotId === null && error === null && <Alert kind="info">{t('snap.none')}</Alert>}

      {clusters.data !== null && snapshotId !== null && (
        <section className="card">
          <table>
            <thead>
              <tr>
                <th>{t('rules.cluster')}</th>
                <th>{t('clusters.members')}</th>
                <th>{t('clusters.version')}</th>
                <th>{t('clusters.model')}</th>
                <th>{t('clusters.policy')}</th>
                <th>{t('clusters.rules')}</th>
                <th>{t('limits.ace')}</th>
                <th>{t('common.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {clusters.data.map((c) => (
                <tr key={c.fmc_id} className={c.fmc_id === clusterId ? 'selected' : ''}>
                  <td>
                    <Ltr>{c.name}</Ltr>
                  </td>
                  <td>
                    {c.members.map((m) => (
                      <div key={m.id} className="small">
                        <Ltr>{m.name}</Ltr> <span className="muted">({m.role})</span>
                      </div>
                    ))}
                  </td>
                  <td>
                    <Ltr>{c.sw_version}</Ltr>
                  </td>
                  <td>{c.model}</td>
                  <td>
                    {c.policies.map((p) =>
                      p.kind === 'unknown' ? (
                        // A linked setting the collector does not read (logging, platform, ...).
                        <div key={p.id} className="small muted">
                          {t('kind.unknown')}: <Ltr>{p.via === 'assignment' ? p.id : p.via.replace(/PolicySetting$/, '')}</Ltr>
                        </div>
                      ) : (
                        <div key={p.id} className="small">
                          <span className="muted">{t(`kind.${p.kind}`)}:</span>{' '}
                          <Link
                            to={`/rules?snapshot=${String(snapshotId)}&cluster=${encodeURIComponent(c.fmc_id)}&policy=${encodeURIComponent(p.id)}`}
                          >
                            <Ltr>{p.name}</Ltr>
                          </Link>
                        </div>
                      ),
                    )}
                  </td>
                  <td>{c.rule_count}</td>
                  <td>
                    <AceGauge cluster={c} />
                  </td>
                  <td>
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => {
                        setClusterId(c.fmc_id);
                      }}
                    >
                      {t('clusters.network')}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {clusterId !== null && <LimitsEditor clusterId={clusterId} />}

      {network.data !== null && (
        <>
          <section className="card">
            <h2>{t('clusters.interfaces')}</h2>
            <table>
              <thead>
                <tr>
                  <th>{t('objects.col.name')}</th>
                  <th>ifname</th>
                  <th>{t('clusters.zone')}</th>
                  <th>{t('clusters.address')}</th>
                  <th>VLAN</th>
                </tr>
              </thead>
              <tbody>
                {network.data.interfaces.map((i) => (
                  <tr key={`${i.kind}-${i.name}`} className={i.enabled ? '' : 'inactive'}>
                    <td>
                      <Ltr>{i.name}</Ltr>
                    </td>
                    <td>
                      <Ltr>{i.ifname}</Ltr>
                    </td>
                    <td>{i.zone ?? '—'}</td>
                    <td>
                      <Ltr>{i.ipv4 ?? '—'}</Ltr>
                    </td>
                    <td>{i.vlan ?? ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
          <RouteLookupCard snapshotId={snapshotId} clusterId={clusterId} network={network.data} />
          <section className="card">
            <h2>{t('clusters.routes')}</h2>
            <RuntimeNote network={network.data} />
            <table>
              <thead>
                <tr>
                  <th>{t('objects.col.kind')}</th>
                  <th>{t('rules.col.dstNet')}</th>
                  <th>ifname</th>
                  <th>{t('clusters.gateway')}</th>
                  <th>{t('clusters.distance')}</th>
                  <th>metric</th>
                </tr>
              </thead>
              <tbody>
                {network.data.routes.map((r, i) => (
                  <tr key={`${r.kind}-${String(i)}`}>
                    <td>
                      {t(`clusters.routeKind.${r.kind}`)}
                      {r.protocol !== '' && <div className="muted small">{r.protocol}</div>}
                    </td>
                    <td>
                      <Ltr>{r.network ?? '—'}</Ltr> {r.network_name !== '' && <span className="muted">({r.network_name})</span>}
                    </td>
                    <td>
                      <Ltr>{r.interface}</Ltr>
                    </td>
                    <td>
                      <Ltr>{r.gateway ?? ''}</Ltr>
                      {r.gateway_is_literal && <span className="chip literal small">{t('clusters.literal')}</span>}
                    </td>
                    <td>{r.distance ?? ''}</td>
                    <td>{r.metric}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
          {network.data.bgp.map((b) => (
            <section key={b.as_number ?? 'bgp'} className="card">
              <h2>
                {t('clusters.bgp')} · AS <Ltr>{b.as_number ?? '?'}</Ltr>
              </h2>
              <p>
                {t('clusters.neighbors')}:{' '}
                {b.neighbors.map((n) => (
                  <span key={n.address} className="chip">
                    <Ltr>
                      {n.address} AS{n.remote_as}
                    </Ltr>
                  </span>
                ))}
              </p>
            </section>
          ))}
        </>
      )}
    </div>
  );
}

function RuntimeNote({ network }: { network: ClusterNetwork }) {
  const { t } = useI18n();
  const runtime = network.runtime;
  if (runtime === null) return <p className="muted small">{t('clusters.runtime.none')}</p>;
  return (
    <p className={runtime.status === 'ok' ? 'muted small' : 'small warn-text'}>
      {t(`clusters.runtime.${runtime.status}`, { count: runtime.routes, device: runtime.device ?? '' })}
    </p>
  );
}

/** Which route, interface and zone the cluster uses for an address (longest prefix). */
function RouteLookupCard({
  snapshotId,
  clusterId,
  network,
}: {
  snapshotId: number | null;
  clusterId: string | null;
  network: ClusterNetwork;
}) {
  const { t, tError } = useI18n();
  const [ip, setIp] = useState('');
  const [result, setResult] = useState<RouteLookup | null>(null);
  const [error, setError] = useState<string | null>(null);
  if (snapshotId === null || clusterId === null) return null;

  async function submit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    try {
      const query = new URLSearchParams({ ip: ip.trim() });
      setResult(
        await api<RouteLookup>(
          `/api/snapshots/${String(snapshotId)}/clusters/${encodeURIComponent(clusterId ?? '')}/route-lookup?${query.toString()}`,
        ),
      );
    } catch (err) {
      setResult(null);
      setError(errorCode(err));
    }
  }

  const best = result?.best ?? null;
  return (
    <section className="card">
      <h2>{t('clusters.lookup')}</h2>
      <form className="row" onSubmit={(e) => void submit(e)}>
        <label>
          {t('clusters.lookupIp')}
          <input dir="ltr" maxLength={15} pattern="[0-9.]+" placeholder="10.20.5.7" value={ip} onChange={(e) => { setIp(e.target.value); }} />
        </label>
        <button type="submit" disabled={ip.trim() === ''}>
          {t('clusters.lookupGo')}
        </button>
      </form>
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      {result !== null && best === null && <p className="muted">{t('clusters.lookupNone')}</p>}
      {best !== null && (
        <p>
          {t('clusters.lookupResult', {
            zone: best.zone ?? '—',
            iface: best.interface || '—',
            network: best.network,
            via: best.gateway ?? t('clusters.routeKind.connected'),
          })}{' '}
          <span className="chip small-chip">{best.protocol}</span>
        </p>
      )}
      {result !== null && network.runtime?.status !== 'ok' && <p className="muted small">{t('clusters.lookupConfigOnly')}</p>}
    </section>
  );
}

function AceGauge({ cluster }: { cluster: Cluster }) {
  const { t } = useI18n();
  if (cluster.ace_total === null) return <span className="muted">—</span>;
  const pct = Math.round((cluster.ace_total * 100) / cluster.ace_limit);
  const band = pct > 100 ? 'bad' : pct > 80 ? 'warn' : 'good';
  return (
    <div>
      <span className={`score score-${band}`}>{pct}%</span>{' '}
      <span className="small">
        {cluster.ace_total.toLocaleString()} / {cluster.ace_limit.toLocaleString()}
      </span>
      <div className="muted small">{cluster.ace_limit_verified ? t('limits.verified') : t('limits.unverified')}</div>
    </div>
  );
}

function LimitsEditor({ clusterId }: { clusterId: string }) {
  const { t, tError } = useI18n();
  const { can } = useAuth();
  const limits = useApi<ClusterLimits>(`/api/clusters/${encodeURIComponent(clusterId)}/limits`);
  const [draft, setDraft] = useState<ClusterLimits | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const current = draft ?? limits.data;
  if (current === null) return null;
  const editable = can('fmc:manage');

  async function save(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    if (current === null) return;
    try {
      await api(`/api/clusters/${encodeURIComponent(clusterId)}/limits`, 'PUT', {
        ace_limit: current.ace_limit,
        ace_limit_verified: current.ace_limit_verified,
        deploy_change_limit: current.deploy_change_limit,
        deploy_limit_verified: current.deploy_limit_verified,
      });
      setMessage(t('settings.saved'));
      setDraft(null);
      limits.reload();
    } catch (err: unknown) {
      setMessage(tError(errorCode(err)));
    }
  }

  const update = (patch: Partial<ClusterLimits>) => {
    setDraft({ ...current, ...patch });
  };
  return (
    <section className="card">
      <h2>{t('limits.title')}</h2>
      {message !== null && <Alert kind="info">{message}</Alert>}
      <form className="grid" onSubmit={(e) => void save(e)} noValidate>
        <label>
          {t('limits.aceLimit')}
          <input
            dir="ltr"
            inputMode="numeric"
            disabled={!editable}
            value={String(current.ace_limit)}
            onChange={(e) => {
              update({ ace_limit: Number(e.target.value.replace(/\D/g, '')) });
            }}
          />
        </label>
        <label className="inline">
          <input
            type="checkbox"
            disabled={!editable}
            checked={current.ace_limit_verified}
            onChange={(e) => {
              update({ ace_limit_verified: e.target.checked });
            }}
          />
          {t('limits.verified')}
        </label>
        <label>
          {t('limits.deployLimit')}
          <input
            dir="ltr"
            inputMode="numeric"
            disabled={!editable}
            value={String(current.deploy_change_limit)}
            onChange={(e) => {
              update({ deploy_change_limit: Number(e.target.value.replace(/\D/g, '')) });
            }}
          />
        </label>
        <label className="inline">
          <input
            type="checkbox"
            disabled={!editable}
            checked={current.deploy_limit_verified}
            onChange={(e) => {
              update({ deploy_limit_verified: e.target.checked });
            }}
          />
          {t('limits.verified')}
        </label>
        {editable && <button type="submit">{t('limits.save')}</button>}
      </form>
    </section>
  );
}
