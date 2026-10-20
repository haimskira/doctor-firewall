import { Link } from 'react-router-dom';

import type { ScoredRule } from '../api/types';
import { Alert, Ltr } from '../components/common';
import { SnapshotPicker } from '../components/inventory';
import { ReasonList, ScoreBadge } from '../components/score';
import { useApi, useSnapshotSelection } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';

/** The optimisation queue: lowest-scoring permit rules first, each deduction explained. */
export function ScoresPage() {
  const { t, tError } = useI18n();
  const { snapshots, snapshotId, setSnapshotId, error: snapError } = useSnapshotSelection();
  const queue = useApi<ScoredRule[]>(snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}/scores?limit=200`);
  const error = snapError ?? queue.error;

  return (
    <div className="stack">
      <div className="row spread">
        <h1>{t('score.title')}</h1>
        <SnapshotPicker snapshots={snapshots} value={snapshotId} onChange={setSnapshotId} />
      </div>
      <p className="muted">{t('score.help')}</p>
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      {snapshotId === null && snapError === null && <Alert kind="info">{t('snap.none')}</Alert>}
      {snapshotId !== null && (
        <section className="card">
          <table>
            <thead>
              <tr>
                <th>{t('score.col')}</th>
                <th>{t('rules.policy')}</th>
                <th>{t('rules.col.index')}</th>
                <th>{t('rules.col.name')}</th>
                <th>{t('assets.tier')}</th>
                <th>{t('score.aces')}</th>
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
