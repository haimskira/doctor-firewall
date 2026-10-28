import { Link } from 'react-router-dom';

import { Alert, Ltr } from '../components/common';
import { SnapshotPicker } from '../components/inventory';
import type { Roadmap } from '../components/roadmap';
import { useApi, useSnapshotSelection } from '../hooks';
import { PolicyPicker, ScopeNote, usePolicyScope } from '../components/policyScope';
import { useI18n } from '../i18n/I18nProvider';

const PREPARE_LINK: Record<Roadmap['prepare'][number]['code'], string> = {
  assets: '/assets',
  limits: '/clusters',
  hits: '/rules',
  fresh: '/snapshots',
};

/** The order of a clean-up project: preparation, then one phase at a time (deploy, collect and
 * analyse again between phases), with what is left in each and a link into its recommendations. */
export function RoadmapPage() {
  const { t, tError } = useI18n();
  const { snapshots, snapshotId, setSnapshotId, error: snapError } = useSnapshotSelection();
  const scope = usePolicyScope(snapshotId);
  const map = useApi<Roadmap>(
    snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}/roadmap${scope.policy === null ? '' : `?policy=${scope.policy}`}`,
  );
  const error = snapError ?? map.error;
  const q = snapshotId === null ? '' : `snapshot=${String(snapshotId)}`;
  const data = map.data;

  return (
    <div className="stack">
      <div className="row spread">
        <h1>{t('road.title')}</h1>
        <SnapshotPicker snapshots={snapshots} value={snapshotId} onChange={setSnapshotId} />
        <PolicyPicker scope={scope} />
      </div>
      <ScopeNote scope={scope} />
      <p className="muted">{t('road.help')}</p>
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      {snapshotId === null && snapError === null && <Alert kind="info">{t('snap.none')}</Alert>}
      {data !== null && (
        <>
          <section className="card road-prepare">
            <h2>
              <span className="road-num">0</span> {t('road.prepare')}
            </h2>
            <ul className="plain-list">
              {data.prepare.map((c) => (
                <li key={c.code} className={c.ok ? 'ok' : 'warn'}>
                  <span aria-hidden="true">{c.ok ? '✓' : '!'}</span> {t(`road.check.${c.code}.${c.ok ? 'ok' : 'todo'}`, c.args)}{' '}
                  {!c.ok && <Link to={c.code === 'hits' || c.code === 'fresh' ? `${PREPARE_LINK[c.code]}?${q}` : PREPARE_LINK[c.code]}>{t(`road.check.${c.code}.go`)}</Link>}
                </li>
              ))}
            </ul>
          </section>
          <ol className="road-phases">
            {data.phases.map((p, i) => (
              <li key={p.name} className={`card road-phase road-${p.status}`} aria-current={p.status === 'current' ? 'step' : undefined}>
                <div className="row spread">
                  <h2>
                    <span className="road-num">{i + 1}</span> {t(`road.phase.${p.name}`)}
                  </h2>
                  <span className="row">
                    <span className={`badge road-status-${p.status}`}>{t(`road.status.${p.status}`)}</span>
                    <span className={`badge behavior-${p.behavior}`}>{t(`road.behavior.${p.behavior}`)}</span>
                  </span>
                </div>
                <p className="muted small">{t(`road.why.${p.name}`)}</p>
                {p.total === 0 ? (
                  <p className="small">{t('road.nothing')}</p>
                ) : (
                  <>
                    <p className="small road-counts">
                      {t('road.counts', { open: p.open, accepted: p.accepted, staged: p.staged, dismissed: p.dismissed })}
                      {p.ace_delta < 0 && <span className="ok"> · {t('road.ace', { ace: (-p.ace_delta).toLocaleString() })}</span>}
                    </p>
                    <div className="chips-inline">
                      {p.kinds.map((k) => (
                        <Link key={k.kind} className="chip" to={`/recommendations?${q}&kind=${k.kind}`}>
                          {t(`rec.kind.${k.kind}`)} <Ltr>({k.open > 0 ? `${String(k.open)}/${String(k.total)}` : String(k.total)})</Ltr>
                        </Link>
                      ))}
                    </div>
                    {p.open > 0 && (
                      <Link className="button-link road-open" to={`/recommendations?${q}&phase=${p.name}&state=open`}>
                        {t('road.openPhase', { count: p.open })}
                      </Link>
                    )}
                  </>
                )}
              </li>
            ))}
          </ol>
          <p className="muted small">{t('road.between')}</p>
        </>
      )}
    </div>
  );
}
