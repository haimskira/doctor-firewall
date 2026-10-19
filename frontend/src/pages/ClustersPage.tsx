import { Link } from 'react-router-dom';

import type { Cluster, ClusterNetwork } from '../api/types';
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
                    {c.policy_fmc_id !== null && (
                      <Link to={`/rules?snapshot=${String(snapshotId)}&cluster=${encodeURIComponent(c.fmc_id)}`}>
                        <Ltr>{c.policy_name ?? c.policy_fmc_id}</Ltr>
                      </Link>
                    )}
                  </td>
                  <td>{c.rule_count}</td>
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
          <section className="card">
            <h2>{t('clusters.routes')}</h2>
            <table>
              <thead>
                <tr>
                  <th>{t('objects.col.kind')}</th>
                  <th>{t('rules.col.dstNet')}</th>
                  <th>ifname</th>
                  <th>{t('clusters.gateway')}</th>
                  <th>metric</th>
                </tr>
              </thead>
              <tbody>
                {network.data.routes.map((r, i) => (
                  <tr key={`${r.kind}-${String(i)}`}>
                    <td>{r.kind}</td>
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
