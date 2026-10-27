import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import type { JobRun, JobsList } from '../api/types';
import { Alert, DateTime } from '../components/common';
import { JobProgress, jobLink, useJobText, useJobs } from '../components/jobs';
import { SortedTable } from '../components/sort';
import { useApi } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';

const STATUS_RANK: Record<JobRun['status'], number> = { running: 0, queued: 1, failed: 2, done: 3 };

function seconds(job: JobRun): number | null {
  if (job.started_at === null) return null;
  const end = job.finished_at === null ? Date.now() : Date.parse(job.finished_at);
  return Math.max(0, Math.round((end - Date.parse(job.started_at)) / 1000));
}

function duration(value: number | null): string {
  if (value === null) return '—';
  return `${String(Math.floor(value / 60))}:${String(value % 60).padStart(2, '0')}`;
}

/** Every background job: what runs now, how far it is, and how recent jobs ended. */
export function JobsPage() {
  const { t, tError } = useI18n();
  const { active } = useJobs();
  const history = useApi<JobsList>('/api/jobs?limit=200');
  const text = useJobText();
  const [, setTick] = useState(0);
  const reload = history.reload;

  // Follow the live poll: while something runs, refresh the full list every 2 s.
  useEffect(() => {
    if (active === 0) return undefined;
    const id = window.setInterval(() => {
      reload();
      setTick((n) => n + 1);
    }, 2000);
    return () => {
      window.clearInterval(id);
    };
  }, [active, reload]);

  const rows = history.data?.rows ?? [];
  return (
    <div className="stack">
      <h1>{t('jobs.title')}</h1>
      <p className="muted">{t('jobs.help')}</p>
      {history.error !== null && <Alert kind="error">{tError(history.error)}</Alert>}
      {history.data !== null && rows.length === 0 && <Alert kind="info">{t('jobs.none')}</Alert>}
      {rows.length > 0 && (
        <section className="card">
          <table>
            <SortedTable
              rows={rows}
              columns={{
                kind: (j) => text.kind(j),
                title: (j) => j.title,
                by: (j) => j.requested_by,
                status: (j) => STATUS_RANK[j.status],
                progress: (j) => j.progress,
                created: (j) => j.created_at,
                duration: (j) => seconds(j),
              }}
              head={(th) => (
                <tr>
                  {th('kind', t('jobs.col.kind'))}
                  {th('title', t('jobs.col.title'))}
                  {th('by', t('jobs.col.by'))}
                  {th('status', t('jobs.col.status'))}
                  {th('progress', t('jobs.col.progress'), true)}
                  {th('created', t('jobs.col.created'), true)}
                  {th('duration', t('jobs.col.duration'), true)}
                </tr>
              )}
            >
              {(job) => (
                <tr key={job.id} className={`job-row job-${job.status}`}>
                  <td>{text.kind(job)}</td>
                  <td>
                    <Link to={jobLink(job)}>
                      <bdi>{job.title}</bdi>
                    </Link>
                  </td>
                  <td>
                    <bdi>{job.requested_by}</bdi>
                  </td>
                  <td>
                    <span className={`badge job-status-${job.status}`}>{t(`jobs.status.${job.status}`)}</span>
                    {job.status === 'failed' && <div className="bad small">{text.error(job)}</div>}
                  </td>
                  <td className="job-cell">
                    {job.status !== 'done' && <JobProgress job={job} />}
                    {(job.status === 'running' || job.status === 'queued') && <div className="muted small">{text.step(job)}</div>}
                  </td>
                  <td>
                    <DateTime value={job.created_at} />
                  </td>
                  <td>
                    <bdi dir="ltr">{duration(seconds(job))}</bdi>
                  </td>
                </tr>
              )}
            </SortedTable>
          </table>
        </section>
      )}
    </div>
  );
}
