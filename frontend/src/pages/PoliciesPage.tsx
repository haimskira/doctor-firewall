import { Link } from 'react-router-dom';
import { SortedTable } from '../components/sort';

import { RULE_POLICY_KINDS } from '../api/types';
import type { PolicyInfo, PolicyKind } from '../api/types';
import { Alert, Ltr } from '../components/common';
import { SnapshotPicker } from '../components/inventory';
import { useApi, useSnapshotSelection } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';

const ORDER: PolicyKind[] = ['access', 'prefilter', 'decryption', 'identity', 'nat', 'intrusion', 'file', 'dns'];

/** Every collected policy, grouped by type, with the clusters it governs. */
export function PoliciesPage() {
  const { t, tError } = useI18n();
  const { snapshots, snapshotId, setSnapshotId, error: snapError } = useSnapshotSelection();
  const policies = useApi<PolicyInfo[]>(snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}/policies`);
  const error = snapError ?? policies.error;
  const byKind = new Map<PolicyKind, PolicyInfo[]>();
  for (const p of policies.data ?? []) {
    byKind.set(p.kind, [...(byKind.get(p.kind) ?? []), p]);
  }

  return (
    <div className="stack">
      <div className="row spread">
        <h1>{t('policies.title')}</h1>
        <SnapshotPicker snapshots={snapshots} value={snapshotId} onChange={setSnapshotId} />
      </div>
      <p className="muted">{t('policies.help')}</p>
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      {snapshotId === null && snapError === null && <Alert kind="info">{t('snap.none')}</Alert>}
      {snapshotId !== null &&
        ORDER.filter((kind) => byKind.has(kind)).map((kind) => (
          <section key={kind} className="card">
            <h2>{t(`kind.${kind}`)}</h2>
            <table>
              <SortedTable
                rows={(byKind.get(kind) ?? [])}
                columns={{ name: (p) => p.name, governs: (p) => p.clusters.length, links: (p) => p.links.length, rules: (p) => p.rule_count }}
                head={(th) => (
                  <tr>
                    {th('name', t('objects.col.name'))}
                    {th('governs', t('policies.governs'), true)}
                    {th('links', t('policies.links'), true)}
                    {th('rules', t('clusters.rules'), true)}
                  </tr>
                )}
              >
                {(p) => (
                  <tr key={p.id}>
                    <td>
                      <Ltr>{p.name}</Ltr>
                      {typeof p.attrs['inspection_mode'] === 'string' && (
                        <div className="muted small">{p.attrs['inspection_mode']}</div>
                      )}
                    </td>
                    <td>
                      {p.clusters.length === 0 ? (
                        <span className="muted">{t('policies.unlinked')}</span>
                      ) : (
                        p.clusters.map((c) => (
                          <span key={c} className="chip">
                            <Ltr>{c}</Ltr>
                          </span>
                        ))
                      )}
                    </td>
                    <td>
                      {p.links.map((l) => (
                        <div key={l.relation} className="small">
                          <Ltr>{l.name}</Ltr> <span className="muted">({l.relation})</span>
                        </div>
                      ))}
                    </td>
                    <td>
                      {RULE_POLICY_KINDS.includes(kind) ? (
                        <Link to={`/rules?snapshot=${String(snapshotId)}&policy=${encodeURIComponent(p.id)}`}>
                          {t('policies.open')} ({p.rule_count})
                        </Link>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                  </tr>
                )}
              </SortedTable>
            </table>
          </section>
        ))}
    </div>
  );
}
