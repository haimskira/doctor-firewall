import { Link, useParams } from 'react-router-dom';
import { SortedTable } from '../components/sort';

import type { ObjectDetail, ObjectRelations } from '../api/types';
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
  const relations = useApi<ObjectRelations>(
    snapshotId === null
      ? null
      : `/api/snapshots/${String(snapshotId)}/objects/${encodeURIComponent(objectId)}/relations`,
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
          <section className="card">
            <div className="row spread">
              <h2>{t('relations.title')}</h2>
              <Link to={`/objects/explore?snapshot=${String(snapshotId)}&object=${encodeURIComponent(d.object.id)}`}>
                {t('explorer.openHere')}
              </Link>
            </div>
            {(relations.data?.issues ?? []).length === 0 ? (
              <p className="muted small">{t('explorer.noIssues')}</p>
            ) : (
              <ul className="plain-list small">
                {(relations.data?.issues ?? []).map((issue) => (
                  <li key={`${issue.kind}-${issue.where_id}-${issue.removed}`}>
                    {t(`relations.issue.${issue.kind}`, { where: issue.where_name, removed: issue.removed, kept: issue.kept })}{' '}
                    {issue.recommendation_id !== null && (
                      <Link to={`/recommendations?snapshot=${String(snapshotId)}&rec=${String(issue.recommendation_id)}`}>
                        {t('relations.fix')}
                      </Link>
                    )}
                  </li>
                ))}
              </ul>
            )}
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
                <SortedTable
                  rows={d.used_by}
                  columns={{ policy: (u) => u.policy_name, index: (u) => u.rule_index, name: (u) => u.rule_name, field: (u) => u.field, via: (u) => u.via_name }}
                  head={(th) => (
                    <tr>
                      {th('policy', t('rules.policy'))}
                      {th('index', t('rules.col.index'), true)}
                      {th('name', t('rules.col.name'))}
                      {th('field', t('objects.col.kind'))}
                      {th('via', t('object.via'))}
                    </tr>
                  )}
                >
                  {(u) => (
                    <tr key={`${u.policy_fmc_id}-${u.rule_id}-${u.field}-${u.via_id}`}>
                      <td>
                        {t(`kind.${u.policy_kind}`)}
                        <div className="muted small">
                          <Ltr>{u.policy_name}</Ltr>
                        </div>
                      </td>
                      <td>{u.rule_index}</td>
                      <td>
                        <Link
                          to={`/rules?snapshot=${String(snapshotId)}&policy=${encodeURIComponent(u.policy_fmc_id)}&q=${encodeURIComponent(u.rule_name)}`}
                        >
                          <Ltr>{u.rule_name}</Ltr>
                        </Link>
                      </td>
                      <td>{t(`field.${u.field}`)}</td>
                      <td>{u.via_id === d.object.id ? t('object.direct') : <Ltr>{u.via_name}</Ltr>}</td>
                    </tr>
                  )}
                </SortedTable>
              </table>
            )}
          </section>
        </>
      )}
    </div>
  );
}
