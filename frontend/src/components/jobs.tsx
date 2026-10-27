import { CheckCircleIcon, CircleNotchIcon, ListChecksIcon, WarningCircleIcon, XIcon } from '@phosphor-icons/react';
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { api } from '../api/client';
import type { JobRun, JobsList } from '../api/types';
import { isMessageKey, useI18n } from '../i18n/I18nProvider';

/* Background jobs, live: a provider polls /api/jobs — every 2 s while something is queued or
   running, every 15 s otherwise, slower while the tab is hidden — and raises a notice when a job
   the user started ends. Pages that start a job call kick() to look right away. */

const FAST_MS = 2000;
const IDLE_MS = 15000;
const HIDDEN_MS = 30000;
const TOAST_MS = 12000;

interface JobsValue {
  jobs: JobRun[];
  active: number;
  /** Deployed batches whose after-deploy watch saw blocked traffic. */
  alerts: number;
  kick: () => void;
}

const JobsContext = createContext<JobsValue>({ jobs: [], active: 0, alerts: 0, kick: () => undefined });

export function useJobs(): JobsValue {
  return useContext(JobsContext);
}

interface Toast {
  job: JobRun;
}

export function JobsProvider({ username, enabled, children }: { username: string; enabled: boolean; children: ReactNode }) {
  const [list, setList] = useState<JobsList>({ active: 0, rows: [], alerts: 0 });
  const [toasts, setToasts] = useState<Toast[]>([]);
  const timer = useRef<number | null>(null);
  const known = useRef(new Map<number, JobRun['status']>());
  const since = useRef(0); // set when polling starts: notices only for jobs that end after
  const poll = useRef<() => void>(() => undefined);

  const schedule = useCallback((active: number) => {
    if (timer.current !== null) window.clearTimeout(timer.current);
    const delay = document.hidden ? HIDDEN_MS : active > 0 ? FAST_MS : IDLE_MS;
    timer.current = window.setTimeout(() => {
      poll.current();
    }, delay);
  }, []);

  useEffect(() => {
    poll.current = () => {
      api<JobsList>('/api/jobs?limit=20')
        .then((next) => {
          const ended: Toast[] = [];
          for (const job of next.rows) {
            const before = known.current.get(job.id);
            const finished = job.status === 'done' || job.status === 'failed';
            const recent = job.finished_at !== null && Date.parse(job.finished_at) >= since.current;
            // Ended since the last look (or started and ended in between), and it is this user's.
            if (finished && job.requested_by === username && ((before !== undefined && before !== job.status) || (before === undefined && recent))) {
              ended.push({ job });
            }
            known.current.set(job.id, job.status);
          }
          if (ended.length > 0) setToasts((current) => [...ended, ...current].slice(0, 4));
          setList(next);
          schedule(next.active);
        })
        .catch(() => {
          schedule(0);
        });
    };
  }, [schedule, username]);

  useEffect(() => {
    if (!enabled) return undefined;
    since.current = Date.now();
    poll.current();
    const onVisible = () => {
      if (!document.hidden) poll.current();
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      document.removeEventListener('visibilitychange', onVisible);
      if (timer.current !== null) window.clearTimeout(timer.current);
    };
  }, [enabled]);

  useEffect(() => {
    if (toasts.length === 0) return undefined;
    const t = window.setTimeout(() => {
      setToasts((current) => current.slice(0, -1));
    }, TOAST_MS);
    return () => {
      window.clearTimeout(t);
    };
  }, [toasts]);

  const kick = useCallback(() => {
    poll.current();
  }, []);
  const value = useMemo(() => ({ jobs: list.rows, active: list.active, alerts: list.alerts ?? 0, kick }), [list, kick]);
  return (
    <JobsContext.Provider value={value}>
      {children}
      <JobToasts
        toasts={toasts}
        onClose={(id) => {
          setToasts((current) => current.filter((x) => x.job.id !== id));
        }}
      />
    </JobsContext.Provider>
  );
}

/** Where the result of a job can be seen. */
export function jobLink(job: JobRun): string {
  if (job.kind === 'collect') return '/snapshots';
  if (job.kind === 'analyze') return job.snapshot_id === null ? '/findings' : `/recommendations?snapshot=${String(job.snapshot_id)}`;
  if (job.kind === 'audit_verify') return '/audit';
  return job.changeset_id === null ? '/deploy' : `/deploy?changeset=${String(job.changeset_id)}`;
}

export function useJobText(): { kind: (job: JobRun) => string; step: (job: JobRun) => string; error: (job: JobRun) => string } {
  const { t } = useI18n();
  return {
    kind: (job) => {
      const key = `jobs.kind.${job.kind}`;
      return isMessageKey(key) ? t(key) : job.kind;
    },
    step: (job) => {
      const args = job.step_args;
      const counted = typeof args['total'] === 'number' || typeof args['seconds'] === 'number';
      const withArgs = `jobs.step.${job.step}.n`;
      const plain = `jobs.step.${job.step}`;
      if (counted && isMessageKey(withArgs)) return t(withArgs, args);
      return isMessageKey(plain) ? t(plain) : job.step;
    },
    error: (job) => {
      if (job.error === null) return '';
      const key = `jobs.error.${job.error}`;
      return isMessageKey(key) ? t(key) : job.error;
    },
  };
}

function elapsed(job: JobRun, now: number): string {
  if (job.started_at === null) return '';
  const end = job.finished_at === null ? now : Date.parse(job.finished_at);
  const seconds = Math.max(0, Math.round((end - Date.parse(job.started_at)) / 1000));
  const m = Math.floor(seconds / 60);
  return `${String(m)}:${String(seconds % 60).padStart(2, '0')}`;
}

export function JobProgress({ job }: { job: JobRun }) {
  const { t } = useI18n();
  const state = job.status === 'failed' ? 'bad' : job.status === 'done' ? 'good' : 'run';
  return (
    <div className="job-progress">
      <div
        className={`gauge gauge-${state === 'bad' ? 'bad' : state === 'good' ? 'good' : 'run'}`}
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={job.progress}
        aria-label={t('jobs.progress')}
      >
        <span style={{ inlineSize: `${String(job.status === 'queued' ? 0 : job.progress)}%` }} />
      </div>
      <span className="job-pct">{job.status === 'queued' ? '' : `${String(job.progress)}%`}</span>
    </div>
  );
}

function StatusIcon({ job }: { job: JobRun }) {
  if (job.status === 'done') return <CheckCircleIcon className="job-icon ok" size={16} aria-hidden="true" />;
  if (job.status === 'failed') return <WarningCircleIcon className="job-icon bad" size={16} aria-hidden="true" />;
  return <CircleNotchIcon className="job-icon spin" size={16} aria-hidden="true" />;
}

/** One job, compact: what, how far, which step, how long. */
export function JobLine({ job, now }: { job: JobRun; now: number }) {
  const { t } = useI18n();
  const text = useJobText();
  return (
    <div className={`job-line job-${job.status}`}>
      <div className="row spread">
        <span>
          <StatusIcon job={job} /> <strong>{text.kind(job)}</strong> · <bdi>{job.title}</bdi>
        </span>
        <span className="muted small">
          <bdi dir="ltr">{elapsed(job, now)}</bdi>
        </span>
      </div>
      {job.status !== 'done' && <JobProgress job={job} />}
      <div className="muted small">
        {job.status === 'failed' ? <span className="bad">{text.error(job)}</span> : job.status === 'done' ? t('jobs.status.done') : text.step(job)}
      </div>
    </div>
  );
}

function useNow(enabled: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!enabled) return undefined;
    const id = window.setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => {
      window.clearInterval(id);
    };
  }, [enabled]);
  return now;
}

/** Top-bar button: running jobs with a spinner and count; the panel lists them live. */
export function JobsIndicator() {
  const { t } = useI18n();
  const { jobs, active } = useJobs();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);
  const now = useNow(open || active > 0);

  useEffect(() => {
    if (!open) return undefined;
    function onPointer(event: MouseEvent) {
      if (ref.current !== null && event.target instanceof Node && !ref.current.contains(event.target)) setOpen(false);
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpen(false);
    }
    document.addEventListener('mousedown', onPointer);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onPointer);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <div className="fmc-jobs" ref={ref}>
      <button
        type="button"
        className={`fmc-icon-btn${active > 0 ? ' busy' : ''}`}
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-label={active > 0 ? t('jobs.indicator', { count: active }) : t('jobs.indicatorIdle')}
        onClick={() => {
          setOpen(!open);
        }}
      >
        {active > 0 ? <CircleNotchIcon size={19} className="spin" aria-hidden="true" /> : <ListChecksIcon size={19} aria-hidden="true" />}
        {active > 0 && (
          <bdi dir="ltr" className="fmc-badge job-badge">
            {active}
          </bdi>
        )}
      </button>
      {open && (
        <div className="fmc-jobs-panel" role="dialog" aria-label={t('jobs.title')}>
          <div className="row spread">
            <strong>{t('jobs.title')}</strong>
            <Link
              to="/jobs"
              onClick={() => {
                setOpen(false);
              }}
            >
              {t('jobs.all')}
            </Link>
          </div>
          {jobs.length === 0 ? (
            <p className="muted small">{t('jobs.none')}</p>
          ) : (
            <ul className="plain-list job-list">
              {jobs.slice(0, 8).map((job) => (
                <li key={job.id}>
                  <Link
                    to={jobLink(job)}
                    className="job-link"
                    onClick={() => {
                      setOpen(false);
                    }}
                  >
                    <JobLine job={job} now={now} />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

function JobToasts({ toasts, onClose }: { toasts: Toast[]; onClose: (id: number) => void }) {
  const { t } = useI18n();
  const text = useJobText();
  if (toasts.length === 0) return null;
  return (
    <div className="job-toasts" aria-live="polite">
      {toasts.map(({ job }) => (
        <div key={job.id} className={`job-toast job-${job.status}`} role="status">
          <StatusIcon job={job} />
          <div className="grow">
            <div>
              <strong>{t(job.status === 'done' ? 'jobs.toast.done' : 'jobs.toast.failed', { kind: text.kind(job) })}</strong>{' '}
              <bdi>{job.title}</bdi>
            </div>
            {job.status === 'failed' && <div className="small">{text.error(job)}</div>}
            <Link to={jobLink(job)} className="small">
              {t('jobs.toast.open')}
            </Link>
          </div>
          <button
            type="button"
            className="link"
            aria-label={t('jobs.toast.close')}
            onClick={() => {
              onClose(job.id);
            }}
          >
            <XIcon size={14} aria-hidden="true" />
          </button>
        </div>
      ))}
    </div>
  );
}

/** Top bar: a deployment whose watch saw blocked traffic (links to the history and its revert). */
export function WatchAlert() {
  const { t } = useI18n();
  const { alerts } = useJobs();
  if (alerts === 0) return null;
  return (
    <span role="alert">
      <Link to="/history" className="watch-alert">
        {t('watch.topAlert', { count: alerts })}
      </Link>
    </span>
  );
}
