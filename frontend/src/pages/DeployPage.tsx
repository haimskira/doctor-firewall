import { useEffect, useState } from 'react';

import { api, errorCode } from '../api/client';
import type { BatchResult, Changeset, ChangesetBatch, ChangesetDetail, PlanOp } from '../api/types';
import { useAuth, useMe } from '../auth/AuthProvider';
import { Alert, DateTime, Ltr } from '../components/common';
import { JobProgress, useJobText, useJobs } from '../components/jobs';
import { tagGroup } from '../components/recommendations';
import { SortedTable } from '../components/sort';
import { useApi, useQueryParam } from '../hooks';
import { isMessageKey, useI18n } from '../i18n/I18nProvider';

const REFRESH_MS = 4000;

/** Human text for one plan operation. */
export function useOpLabel(): (op: PlanOp) => string {
  const { t } = useI18n();
  return (op) => {
    const key = `dep.op.${op.op}`;
    const name = op.name ?? op.rule_name ?? op.object_name ?? '';
    return isMessageKey(key) ? t(key, { name, from: op.object_name ?? op.rule_name ?? '' }) : `${op.op} ${name}`;
  };
}

/**
 * Deployment (the FMC "Deploy" area): changesets staged from accepted recommendations,
 * their batches under the deploy limit, four-eyes approval, write + deploy, and results.
 */
export function DeployPage() {
  const { t, tError } = useI18n();
  const [selectedParam, setSelected] = useQueryParam('changeset');
  const list = useApi<Changeset[]>('/api/changesets');
  const selected = selectedParam !== null && /^\d+$/.test(selectedParam) ? Number(selectedParam) : null;
  const detail = useApi<ChangesetDetail>(selected === null ? null : `/api/changesets/${String(selected)}`);
  const running = (detail.data?.batches ?? []).some((b) => b.status === 'running' || b.status === 'approved');
  const reloadList = list.reload;
  const reloadDetail = detail.reload;

  // While a batch is queued or running, follow its progress.
  useEffect(() => {
    if (!running) return undefined;
    const timer = window.setInterval(() => {
      reloadDetail();
      reloadList();
    }, REFRESH_MS);
    return () => {
      window.clearInterval(timer);
    };
  }, [running, reloadDetail, reloadList]);

  return (
    <div className="stack">
      <div>
        <h1>{t('dep.title')}</h1>
        <p className="muted small">{t('dep.help')}</p>
      </div>
      {list.error !== null && <Alert kind="error">{tError(list.error)}</Alert>}
      {list.data !== null && list.data.length === 0 && <Alert kind="info">{t('dep.none')}</Alert>}
      {list.data !== null && list.data.length > 0 && (
        <section className="card">
          <table>
            <SortedTable
              rows={list.data}
              columns={{ id: (cs) => cs.id, title: (cs) => cs.title, ticket: (cs) => cs.ticket_id, status: (cs) => cs.status, ops: (cs) => cs.op_count, batches: (cs) => cs.batches.length, author: (cs) => cs.created_by, created: (cs) => cs.created_at }}
              head={(th) => (
                <tr>
                  {th('id', '#', true)}
                  {th('title', t('dep.col.title'))}
                  {th('ticket', t('dep.col.ticket'))}
                  {th('status', t('dep.col.status'))}
                  {th('ops', t('dep.col.ops'), true)}
                  {th('batches', t('dep.col.batches'), true)}
                  {th('author', t('dep.col.author'))}
                  {th('created', t('dep.col.created'), true)}
                </tr>
              )}
            >
              {(cs) => (
                <tr key={cs.id} className={cs.id === selected ? 'selected' : ''}>
                  <td>{cs.id}</td>
                  <td>
                    <button
                      type="button"
                      className="link"
                      aria-pressed={cs.id === selected}
                      onClick={() => {
                        setSelected(String(cs.id));
                      }}
                    >
                      <bdi>{cs.title}</bdi>
                    </button>
                  </td>
                  <td>
                    <Ltr>{cs.ticket_id}</Ltr>
                  </td>
                  <td>
                    <span className={`badge cs-${cs.status}`}>{t(`dep.status.${cs.status}`)}</span>
                  </td>
                  <td>{cs.op_count}</td>
                  <td>
                    {cs.batches.filter((b) => b.status === 'deployed').length} / {cs.batches.length}
                  </td>
                  <td>
                    <bdi>{cs.created_by}</bdi>
                  </td>
                  <td>
                    <DateTime value={cs.created_at} />
                  </td>
                </tr>
              )}
            </SortedTable>
          </table>
        </section>
      )}
      {detail.error !== null && <Alert kind="error">{tError(detail.error)}</Alert>}
      {detail.data !== null && (
        <ChangesetPanel
          key={detail.data.id}
          cs={detail.data}
          onChanged={() => {
            reloadDetail();
            reloadList();
          }}
        />
      )}
    </div>
  );
}

function ChangesetPanel({ cs, onChanged }: { cs: ChangesetDetail; onChanged: () => void }) {
  const { t, tError } = useI18n();
  const { can } = useAuth();
  const me = useMe();
  const jobs = useJobs();
  const jobText = useJobText();
  const running = jobs.jobs.find((j) => j.changeset_id === cs.id && (j.status === 'queued' || j.status === 'running'));
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const isAuthor = cs.created_by === me.username;
  const open = cs.status === 'open' || cs.status === 'in_progress';
  const opLabel = useOpLabel();
  const batchError = (raw: string) => {
    const [code = '', ...rest] = raw.split(': ');
    const detail = rest.join(': ').replace(/^drift: /, '');
    const key = `dep.err.${code}`;
    return isMessageKey(key) ? t(key, { detail }) : t('dep.error', { error: raw });
  };

  async function act(path: string, confirmText?: string) {
    if (confirmText !== undefined && !window.confirm(confirmText)) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await api(path, 'POST');
      jobs.kick();
      if (path.endsWith('/run')) setNotice(t('dep.queued'));
      if (path.endsWith('/rollback')) setNotice(t('dep.rollbackQueued'));
      onChanged();
    } catch (err) {
      setError(errorCode(err));
    } finally {
      setBusy(false);
    }
  }

  const base = `/api/changesets/${String(cs.id)}`;
  const firstOpen = cs.batches.find((b) => b.status !== 'deployed');

  return (
    <section className="card stack" aria-label={cs.title}>
      <div className="row spread">
        <div>
          <h2>
            #{cs.id} <bdi>{cs.title}</bdi>
          </h2>
          <div className="rec-facts small">
            <span className={`badge cs-${cs.status}`}>{t(`dep.status.${cs.status}`)}</span>
            <span>
              <span className="muted">{t('dep.col.ticket')}: </span>
              <Ltr>{cs.ticket_id}</Ltr>
            </span>
            <span>
              {t('dep.limit', { limit: cs.deploy_limit })}
              {!cs.deploy_limit_verified && <span className="muted"> ({t('dep.limitUnverified')})</span>}
            </span>
            <span className="muted">
              {t('dep.col.author')}: <bdi>{cs.created_by}</bdi>
            </span>
          </div>
        </div>
        {open && can('changeset:write') && (
          <button type="button" className="danger" disabled={busy} onClick={() => void act(`${base}/cancel`)}>
            {t('dep.cancel')}
          </button>
        )}
      </div>
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      {notice !== null && <Alert kind="success">{notice}</Alert>}
      {isAuthor && open && can('deploy:approve') && <Alert kind="info">{t('dep.authorNote')}</Alert>}

      {cs.batches.map((b) => {
        const items = cs.items.filter((i) => i.batch_seq === b.seq);
        const isNext = firstOpen?.seq === b.seq;
        const mayAct = open && can('deploy:approve') && !isAuthor && isNext;
        return (
          <article key={b.seq} className={`batch batch-${b.status}`} aria-label={t('dep.batch', { seq: b.seq })}>
            <header className="row spread">
              <div className="rec-facts">
                <strong>{t('dep.batch', { seq: b.seq })}</strong>
                <BatchBadge status={b.status} />
                <span className="muted small">{t('dep.batchOps', { count: b.op_count, limit: b.deploy_limit })}</span>
                {b.approved_by !== null && (
                  <span className="muted small">{t('dep.approvedBy', { user: b.approved_by })}</span>
                )}
              </div>
              <div className="row">
                {mayAct && b.status === 'pending' && (
                  <button type="button" disabled={busy} onClick={() => void act(`${base}/batches/${String(b.seq)}/approve`)}>
                    {t('dep.approve')}
                  </button>
                )}
                {mayAct && b.status === 'approved' && (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() =>
                      void act(
                        `${base}/batches/${String(b.seq)}/run`,
                        t('dep.runConfirm', { seq: b.seq, count: b.op_count }),
                      )
                    }
                  >
                    {t('dep.run')}
                  </button>
                )}
                {b.rollback_resumable && can('deploy:approve') && (
                  <button
                    type="button"
                    className="danger"
                    disabled={busy}
                    onClick={() =>
                      void act(
                        `${base}/batches/${String(b.seq)}/rollback`,
                        t('dep.rollbackConfirm', { seq: b.seq, count: b.undo_pending }),
                      )
                    }
                  >
                    {t('dep.rollback')}
                  </button>
                )}
              </div>
            </header>
            {b.error !== null && <Alert kind="error">{batchError(b.error)}</Alert>}
            {running !== undefined && (b.status === 'running' || b.status === 'approved') && running.title.endsWith(` · ${String(b.seq)}`) && (
              <div className="batch-job">
                <JobProgress job={running} />
                <span className="muted small">{jobText.step(running)}</span>
              </div>
            )}
            {b.rollback_resumable && <Alert kind="error">{t('dep.rollbackPending', { count: b.undo_pending })}</Alert>}
            <div className="batch-body">
              <div>
                <h3>{t('dep.items')}</h3>
                <ul className="plain-list small">
                  {items.map((i) => (
                    <li key={i.fingerprint}>
                      <span className={`rec-tag tag-${tagGroup(i.kind)}`}>{t(`rec.kind.${i.kind}`)}</span> <bdi>{i.title}</bdi>
                      <ul className="plain-list ops">
                        {(i.plan.ops ?? []).map((op, n) => (
                          <li key={`${i.fingerprint}-${String(n)}`} className="muted">
                            <Ltr>{opLabel(op)}</Ltr>
                          </li>
                        ))}
                      </ul>
                    </li>
                  ))}
                </ul>
              </div>
              {b.results.length > 0 && (
                <div>
                  <h3>{t('dep.results')}</h3>
                  <ResultList results={b.results} />
                </div>
              )}
            </div>
          </article>
        );
      })}
    </section>
  );
}

function BatchBadge({ status }: { status: ChangesetBatch['status'] }) {
  const { t } = useI18n();
  return <span className={`badge batch-badge batch-${status}`}>{t(`dep.batch.${status}`)}</span>;
}

function ResultList({ results }: { results: BatchResult[] }) {
  const { t } = useI18n();
  const label = (r: BatchResult) => {
    const key = `dep.op.${r.op}`;
    const name = r.name ?? r.detail ?? '';
    return isMessageKey(key) ? t(key, { name, from: '' }) : `${r.op} ${name}`;
  };
  return (
    <ul className="plain-list small">
      {results.map((r, n) => (
        <li key={`${r.op}-${String(n)}`} className={r.op === 'undo_failed' ? 'bad' : ''}>
          <Ltr>{label(r)}</Ltr>
        </li>
      ))}
    </ul>
  );
}
