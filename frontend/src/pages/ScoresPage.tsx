import { Link } from 'react-router-dom';

import type { ScoredRule } from '../api/types';
import { Alert, Ltr } from '../components/common';
import { SnapshotPicker } from '../components/inventory';
import { ReasonList, ScoreBadge } from '../components/score';
import { SortTh, useServerSort } from '../components/sort';
import { useApi, useSnapshotSelection } from '../hooks';
import { PolicyPicker, ScopeNote, usePolicyScope } from '../components/policyScope';
import { useI18n } from '../i18n/I18nProvider';

const SORTS = ['score', 'policy', 'index', 'name', 'ace'] as const;

/** The optimisation queue: lowest-scoring permit rules first, each deduction explained. */
export function ScoresPage() {
  const { t, tError } = useI18n();
  const { snapshots, snapshotId, setSnapshotId, error: snapError } = useSnapshotSelection();
  const sort = useServerSort(SORTS);
  const scope = usePolicyScope(snapshotId);
  const params = new URLSearchParams({ limit: '200', ...sort.query });
  if (scope.policy !== null) params.set('policy_id', scope.policy);
  const queue = useApi<ScoredRule[]>(snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}/scores?${params.toString()}`);
  const error = snapError ?? queue.error;

  return (
    <div className="stack">
      <div className="row spread">
        <h1>{t('score.title')}</h1>
        <div className="row page-filters">
          <SnapshotPicker snapshots={snapshots} value={snapshotId} onChange={setSnapshotId} />
          <PolicyPicker scope={scope} />
        </div>
      </div>
      <ScopeNote scope={scope} />
      <p className="muted">{t('score.help')}</p>
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      {snapshotId === null && snapError === null && <Alert kind="info">{t('snap.none')}</Alert>}
      {snapshotId !== null && (
        <section className="card">
          <table>
            <thead>
              <tr>
                <SortTh label={t('score.col')} sortKey="score" state={sort.state} onSort={sort.onSort} numeric />
                <SortTh label={t('rules.policy')} sortKey="policy" state={sort.state} onSort={sort.onSort} />
                <SortTh label={t('rules.col.index')} sortKey="index" state={sort.state} onSort={sort.onSort} numeric />
                <SortTh label={t('rules.col.name')} sortKey="name" state={sort.state} onSort={sort.onSort} />
                <th>{t('assets.tier')}</th>
                <SortTh label={t('score.aces')} sortKey="ace" state={sort.state} onSort={sort.onSort} numeric />
                <th>{t('score.reasons')}</th>
              </tr>
            </thead>
            <tbody>
              {(queue.data ?? []).map((r) => (
                <tr key={`${r.policy_fmc_id}-${r.rule_id}`}>
                  <td>
                    <ScoreBadge score={r.score} />
                  </td>
                  <td>
                    <Ltr>{r.policy_name}</Ltr>
                  </td>
                  <td>{r.rule_index}</td>
                  <td>
                    <Link
                      to={`/rules?snapshot=${String(snapshotId)}&policy=${encodeURIComponent(r.policy_fmc_id)}&q=${encodeURIComponent(r.rule_name)}`}
                    >
                      <Ltr>{r.rule_name}</Ltr>
                    </Link>
                  </td>
                  <td>
                    {r.dst_tiers.map((tier) => (
                      <span key={tier} className={`tier tier-${tier.toLowerCase()}`}>
                        {tier}
                      </span>
                    ))}
                  </td>
                  <td>{r.ace_count.toLocaleString()}</td>
                  <td>
                    <ReasonList reasons={r.reasons} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
