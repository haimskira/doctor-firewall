import { Link, useParams } from 'react-router-dom';

import type { ObjectDetail } from '../api/types';
import { Alert, Ltr } from '../components/common';
import { RefChip } from '../components/inventory';
import { useApi, useSnapshotSelection } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';

/** Impact analysis for one object: what it contains, what contains it, who uses it. */
export function ObjectDetailPage() {
  const { t, tError } = useI18n();
  const { objectId = '' } = useParams();
  const { snapshotId, error: snapError } = useSnapshotSelection();
  const detail = useApi<ObjectDetail>(
    snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}/objects/${encodeURIComponent(objectId)}`,
  );
  const error = snapError ?? detail.error;
  const d = detail.data;
  const byDepth = new Map<number, ObjectDetail['member_of']>();
  for (const edge of d?.member_of ?? []) {
    byDepth.set(edge.depth, [...(byDepth.get(edge.depth) ?? []), edge]);
  }

  return (
    <div className="stack">
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      {d !== null && snapshotId !== null && (
        <>
          <h1>
            <Ltr>{d.object.name}</Ltr> <span className="muted small">{d.object.kind}</span>
          </h1>
          <section className="card">
            {d.object.value !== null && (
              <p>
                <Ltr>{d.object.value}</Ltr>
              </p>
            )}
            {d.object.stub && <p className="muted">{t('objects.stub')}</p>}
          </section>

          {d.members.length > 0 && (
            <section className="card">
              <h2>{t('object.members')}</h2>
              <span className="chips-inline">
                {d.members.map((m, i) => (
                  <RefChip key={`${m.id ?? m.literal ?? ''}-${String(i)}`} item={m} snapshotId={snapshotId} />
                ))}
              </span>
            </section>
          )}

          <section className="card">
            <h2>{t('object.memberOf')}</h2>
            {byDepth.size === 0 ? (
              <p className="muted">{t('object.noMembers')}</p>
            ) : (
              <ol className="tree">
                {[...byDepth.entries()].map(([depth, edges]) => (
                  <li key={depth}>
                    {edges.map((e) => (
                      <Link
                        key={`${e.group_id}-${e.child_id}`}
                        className="chip obj"
                        to={`/objects/${encodeURIComponent(e.group_id)}?snapshot=${String(snapshotId)}`}
                      >
                        <Ltr>{e.group_name}</Ltr>
                      </Link>
                    ))}
                  </li>
                ))}
              </ol>
            )}
          </section>

          <section className="card">
            <h2>{t('object.usedBy', { count: d.used_by_total })}</h2>
            {d.used_by.length === 0 ? (
              <p className="muted">{t('object.notUsed')}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>{t('rules.col.index')}</th>
                    <th>{t('rules.col.name')}</th>
                    <th>{t('objects.col.kind')}</th>
                    <th>{t('object.via')}</th>
                  </tr>
                </thead>
                <tbody>
                  {d.used_by.map((u) => (
                    <tr key={`${u.policy_fmc_id}-${u.rule_id}-${u.field}-${u.via_id}`}>
                      <td>{u.rule_index}</td>
                      <td>
                        <Link to={`/rules?snapshot=${String(snapshotId)}&q=${encodeURIComponent(u.rule_name)}`}>
                          <Ltr>{u.rule_name}</Ltr>
                        </Link>
                      </td>
                      <td>{t(`field.${u.field}`)}</td>
                      <td>{u.via_id === d.object.id ? t('object.direct') : <Ltr>{u.via_name}</Ltr>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </>
      )}
    </div>
  );
}
