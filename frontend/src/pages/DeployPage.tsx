import { useEffect, useState } from 'react';

import { api, errorCode } from '../api/client';
import type { BatchResult, Changeset, ChangesetBatch, ChangesetDetail, PlanOp, TrafficProof } from '../api/types';
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
  const [heldParam] = useQueryParam('held');
  const list = useApi<Changeset[]>('/api/changesets');
  const selected = selectedParam !== null && /^\d+$/.test(selectedParam) ? Number(selectedParam) : null;
  const detail = useApi<ChangesetDetail>(selected === null ? null : `/api/changesets/${String(selected)}`);
  // Follow while a batch runs or its traffic proof is still being computed.
  const running = (detail.data?.batches ?? []).some(
    (b) => b.status === 'running' || b.status === 'approved' || (b.status === 'pending' && b.proof == null),
  );
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
      {heldParam !== null && /^\d+$/.test(heldParam) && (
        <Alert kind="info">{t('dep.held', { count: Number(heldParam) })}</Alert>
      )}
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

  const [acknowledged, setAcknowledged] = useState(false);

  async function act(path: string, confirmText?: string, body?: unknown) {
    if (confirmText !== undefined && !window.confirm(confirmText)) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await api(path, 'POST', body);
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
        {(open || cs.status === 'failed') && can('changeset:write') && (
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
          <article key={b.seq} className={`batch batch-${b.status}`} aria-label={t('dep.batch', { cs: cs.id, seq: b.seq })}>
            <header className="row spread">
              <div className="rec-facts">
                <strong>{t('dep.batch', { cs: cs.id, seq: b.seq })}</strong>
                <BatchBadge status={b.status} />
                <span className="muted small">{t('dep.batchOps', { count: b.op_count, limit: b.deploy_limit })}</span>
                {b.approved_by !== null && (
                  <span className="muted small">{t('dep.approvedBy', { user: b.approved_by })}</span>
                )}
              </div>
              <div className="row">
                {mayAct && b.status === 'pending' && (
                  <button
                    type="button"
                    disabled={busy || !approvable(b, acknowledged)}
                    title={approvable(b, acknowledged) ? undefined : t('dep.proof.blocked')}
                    onClick={() =>
                      void act(
                        `${base}/batches/${String(b.seq)}/approve`,
                        undefined,
                        b.proof?.behavior === 'changes' ? { acknowledge_change: acknowledged } : undefined,
                      )
                    }
                  >
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
                        t('dep.runConfirm', { cs: cs.id, seq: b.seq, count: b.op_count }),
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
                        t('dep.rollbackConfirm', { cs: cs.id, seq: b.seq, count: b.undo_pending }),
                      )
                    }
                  >
                    {t('dep.rollback')}
                  </button>
                )}
              </div>
            </header>
            {b.error !== null && <Alert kind="error">{batchError(b.error)}</Alert>}
            <ProofView
              batch={b}
              canAcknowledge={mayAct && b.status === 'pending'}
              acknowledged={acknowledged}
              onAcknowledge={setAcknowledged}
            />
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

/** A batch may be approved once its proof exists: no flow changed, or changes acknowledged. */
function approvable(b: ChangesetBatch, acknowledged: boolean): boolean {
  const proof = b.proof;
  if (proof == null) return false;
  if (proof.differences === 0) return true;
  return proof.behavior === 'changes' && acknowledged;
}

function verdictText(t: ReturnType<typeof useI18n>['t'], verdict: (string | null)[]): string {
  const [first, ips, file] = verdict;
  const action = first ?? '';
  const base = action.startsWith('DEFAULT:') ? t('dep.proof.default', { action: action.slice(8) }) : action;
  const inspection = [ips != null ? 'IPS' : null, file != null ? t('dep.proof.file') : null].filter(Boolean);
  return inspection.length > 0 ? `${base} + ${inspection.join(' + ')}` : base;
}

function ProofDiffs({ proof }: { proof: TrafficProof }) {
  const { t } = useI18n();
  const rows = proof.policies.flatMap((p) => p.differences.map((d) => ({ policy: p.name, d })));
  if (rows.length === 0) return null;
  return (
    <table className="proof-diffs">
      <thead>
        <tr>
          <th>{t('dep.proof.flow')}</th>
          <th>{t('dep.proof.before')}</th>
          <th>{t('dep.proof.after')}</th>
        </tr>
      </thead>
      <tbody>
        {rows.slice(0, 20).map(({ policy, d }, n) => (
          <tr key={String(n)}>
            <td>
              <Ltr>
                {String(d.flow['src'])} → {String(d.flow['dst'])} {String(d.flow['service'])}
              </Ltr>
              <div className="muted small">
                <bdi>{policy}</bdi>
                {Object.entries(d.flow)
                  .filter(([k]) => !['src', 'dst', 'service'].includes(k))
                  .map(([k, v]) => ` · ${k}: ${String(v)}`)
                  .join('')}
              </div>
            </td>
            <td>
              {verdictText(t, d.before.verdict)}
              {d.before.rule !== null && <div className="muted small"><bdi>{d.before.rule}</bdi></div>}
            </td>
            <td>
              {verdictText(t, d.after.verdict)}
              {d.after.rule !== null && <div className="muted small"><bdi>{d.after.rule}</bdi></div>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** The batch's traffic proof: what was checked, and every flow that changes. */
function ProofView({
  batch,
  canAcknowledge,
  acknowledged,
  onAcknowledge,
}: {
  batch: ChangesetBatch;
  canAcknowledge: boolean;
  acknowledged: boolean;
  onAcknowledge: (value: boolean) => void;
}) {
  const { t } = useI18n();
  const proof = batch.proof;
  const after = batch.proof_after;
  if (proof === undefined) return null;
  if (proof === null) {
    return <p className="proof proof-pending muted small">{t('dep.proof.pending')}</p>;
  }
  const scope = proof.exhaustive ? t('dep.proof.exhaustive') : t('dep.proof.sampled');
  return (
    <div className="stack proof-block">
      {proof.differences === 0 ? (
        <p className="proof proof-ok">
          {proof.touched === 0 && (proof.rules ?? 0) > 0
            ? t('dep.proof.identical', { rules: proof.rules ?? 0 })
            : t('dep.proof.ok', { flows: proof.flows })}{' '}
          <span className="muted small">({scope})</span>
        </p>
      ) : proof.behavior === 'preserves' ? (
        <div className="proof proof-bad">
          <p>{t('dep.proof.unexpected', { count: proof.differences })}</p>
          <ProofDiffs proof={proof} />
        </div>
      ) : (
        <div className="proof proof-changes">
          <p>{t('dep.proof.changes', { count: proof.differences, flows: proof.flows })}</p>
          <ProofDiffs proof={proof} />
          {batch.changes_acknowledged_by != null ? (
            <p className="small">{t('dep.proof.acknowledgedBy', { user: batch.changes_acknowledged_by })}</p>
          ) : (
            canAcknowledge && (
              <label className="inline-field">
                <input
                  type="checkbox"
                  checked={acknowledged}
                  onChange={(e) => {
                    onAcknowledge(e.target.checked);
                  }}
                />
                {t('dep.proof.acknowledge')}
              </label>
            )
          )}
        </div>
      )}
      {after != null && (
        <p className={`proof ${after.ok ? 'proof-ok' : 'proof-bad'} small`}>
          {after.ok
            ? after.touched === 0 && (after.rules ?? 0) > 0
              ? t('dep.proof.afterIdentical', { rules: after.rules ?? 0 })
              : t('dep.proof.afterOk', { flows: after.flows })
            : t('dep.proof.afterBad', { count: after.differences })}
        </p>
      )}
    </div>
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
