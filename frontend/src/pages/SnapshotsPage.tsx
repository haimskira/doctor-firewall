import { useEffect, useState } from 'react';
import { JobProgress, useJobText, useJobs } from '../components/jobs';
import { SortedTable } from '../components/sort';

import { api, errorCode } from '../api/client';
import type { Snapshot } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { Alert, DateTime, Ltr } from '../components/common';
import { useApi } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';

interface ConnectionName {
  id: number;
  name: string;
  sync_interval_minutes: number | null;
}

const POLL_MS = 3000;

export function SnapshotsPage() {
  const { t, tError } = useI18n();
  const { can } = useAuth();
  const connections = useApi<ConnectionName[]>('/api/connections');
  const snapshots = useApi<Snapshot[]>('/api/snapshots?limit=100');
  const [message, setMessage] = useState<{ kind: 'error' | 'success'; text: string } | null>(null);
  const reloadSnapshots = snapshots.reload;
  const jobs = useJobs();
  const jobText = useJobText();
  const pulling = (snapshots.data ?? []).some((s) => s.status === 'pending' || s.status === 'running');
  // Keep following while a pull or its analysis runs (the analysis ends after the pull).
  const active = pulling || jobs.jobs.some((j) => j.snapshot_id !== null && (j.status === 'queued' || j.status === 'running'));

  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(reloadSnapshots, POLL_MS);
    return () => {
      window.clearInterval(timer);
    };
  }, [active, reloadSnapshots]);

  async function trigger(path: string) {
    setMessage(null);
    try {
      await api<Snapshot>(path, 'POST');
      setMessage({ kind: 'success', text: t('snap.started') });
      reloadSnapshots();
      jobs.kick();
    } catch (err: unknown) {
      setMessage({ kind: 'error', text: tError(errorCode(err)) });
    }
  }

  const error = connections.error ?? snapshots.error;
  return (
    <div className="stack">
      <h1>{t('snap.title')}</h1>
      <p className="muted">{t('snap.help')}</p>
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      {message !== null && <Alert kind={message.kind}>{message.text}</Alert>}

      {can('collect:run') && (
        <section className="card row">
          {(connections.data ?? []).map((c) => (
            <button key={c.id} type="button" onClick={() => void trigger(`/api/fmc/connections/${String(c.id)}/collect`)}>
              {t('snap.collect')}: {c.name}
            </button>
          ))}
        </section>
      )}

      <section className="card">
        {(snapshots.data ?? []).length === 0 ? (
          <p className="muted">{t('common.none')}</p>
        ) : (
          <table>
            <SortedTable
              rows={(snapshots.data ?? [])}
              columns={{ id: (s) => s.id, fmc: (s) => s.connection_name, status: (s) => s.status, created: (s) => s.created_at, finished: (s) => s.finished_at, by: (s) => s.requested_by }}
              head={(th) => (
                <tr>
                  {th('id', '#', true)}
                  {th('fmc', 'FMC')}
                  {th('status', t('audit.outcome'))}
                  {th('created', t('snap.created'), true)}
                  {th('finished', t('snap.finished'), true)}
                  {th('by', t('snap.by'))}
                  <th>{t('common.actions')}</th>
                </tr>
              )}
            >
              {(s) => (
                <tr key={s.id}>
                  <td>{s.id}</td>
                  <td>
                    {s.connection_name}
                    {s.fmc_version !== null && (
                      <div className="muted small">
                        <Ltr>{s.fmc_version}</Ltr>
                      </div>
                    )}
                  </td>
                  <td>
                    <span className={`badge status-${s.status}`}>{t(`snap.status.${s.status}`)}</span>
                    {s.status === 'complete' && (
                      <div className="small">
                        {t('snap.stats', {
                          rules: s.stats.rules ?? 0,
                          objects: s.stats.objects ?? 0,
                          clusters: s.stats.clusters ?? 0,
                        })}
                        {s.analyzed_at === null && <span className="muted"> · {t('snap.analyzing')}</span>}
                      </div>
                    )}
                    {s.error !== null && <div className="bad small">{tError(s.error)}</div>}
                    {jobs.jobs
                      .filter((j) => j.snapshot_id === s.id && (j.status === 'queued' || j.status === 'running'))
                      .slice(0, 1)
                      .map((j) => (
                        <div key={j.id} className="small">
                          <JobProgress job={j} />
                          <span className="muted">
                            {jobText.kind(j)}: {jobText.step(j)}
                          </span>
                        </div>
                      ))}
                  </td>
                  <td>
                    <DateTime value={s.created_at} />
                  </td>
                  <td>
                    <DateTime value={s.finished_at} />
                  </td>
                  <td>
                    <Ltr>{s.requested_by}</Ltr>
                  </td>
                  <td>
                    {s.status === 'failed' && can('collect:run') && (
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => void trigger(`/api/snapshots/${String(s.id)}/resume`)}
                      >
                        {t('snap.resume')}
                      </button>
                    )}
                  </td>
                </tr>
              )}
            </SortedTable>
          </table>
        )}
      </section>
    </div>
  );
}
