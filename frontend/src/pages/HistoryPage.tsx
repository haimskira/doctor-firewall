import { useState } from 'react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { api, errorCode } from '../api/client';
import { useAuth } from '../auth/AuthProvider';
import { Alert, DateTime, Ltr } from '../components/common';
import { useJobs } from '../components/jobs';
import { SortedTable } from '../components/sort';
import { useApi } from '../hooks';
import { isMessageKey, useI18n } from '../i18n/I18nProvider';
import type { MessageKey } from '../i18n/messages';

interface HistoryEntry {
  changeset_id: number;
  title: string;
  ticket_id: string;
  created_by: string;
  snapshot_id: number | null;
  seq: number;
  status: string;
  op_count: number;
  approved_by: string | null;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  proof: { ok: boolean; flows: number; differences: number; behavior: string } | null;
  proof_after: { ok: boolean; flows: number; differences: number } | null;
  revert_blocker: string | null;
  watch?: Watch | null;
}

interface WatchAlertRow {
  id: string;
  name: string;
  index: number;
  new_hits: number;
  expected: number;
}

interface Watch {
  status: 'watching' | 'ok' | 'alert' | 'dismissed' | 'ended';
  until: string;
  checks: number;
  last_at: string | null;
  rules: number;
  blocks: number;
  alerts: WatchAlertRow[];
  error: string | null;
  dismissed_by: string | null;
}

interface Change {
  op: string;
  label: string;
  what: 'rule' | 'object';
  action: 'created' | 'changed' | 'deleted';
  fields: { field: string; before: string | null; after: string | null }[];
  undone: boolean;
}

/** Every batch that ran: what it changed (before / after), its traffic proof, and reverting. */
export function HistoryPage() {
  const { t, tError } = useI18n();
  const { can } = useAuth();
  const jobs = useJobs();
  const history = useApi<HistoryEntry[]>('/api/history?limit=200');
  const [open, setOpen] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const approver = can('deploy:approve');

  async function dismiss(e: HistoryEntry) {
    if (!window.confirm(t('watch.dismissConfirm', { cs: e.changeset_id, seq: e.seq }))) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await api(`/api/changesets/${String(e.changeset_id)}/batches/${String(e.seq)}/watch/dismiss`, 'POST');
      setNotice(t('watch.dismissed'));
      jobs.kick();
      history.reload();
    } catch (err) {
      setError(errorCode(err));
    } finally {
      setBusy(false);
    }
  }

  async function post(path: string, confirmText: string, body?: unknown) {
    if (!window.confirm(confirmText)) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const out = await api<{ batches: unknown[] }>(path, 'POST', body);
      setNotice(t('hist.revertQueued', { count: out.batches.length }));
      jobs.kick();
      history.reload();
    } catch (err) {
      setError(errorCode(err));
    } finally {
      setBusy(false);
    }
  }

  const rows = history.data ?? [];
  return (
    <div className="stack">
      <h1>{t('hist.title')}</h1>
      <p className="muted">{t('hist.help')}</p>
      {(history.error ?? error) !== null && <Alert kind="error">{tError(history.error ?? error ?? '')}</Alert>}
      {notice !== null && <Alert kind="success">{notice}</Alert>}
      {history.data !== null && rows.length === 0 && <Alert kind="info">{t('hist.none')}</Alert>}
      {rows.length > 0 && (
        <section className="card">
          <table>
            <SortedTable
              rows={rows}
              columns={{
                when: (e) => e.finished_at ?? e.started_at,
                title: (e) => e.title,
                status: (e) => e.status,
                ops: (e) => e.op_count,
              }}
              head={(th) => (
                <tr>
                  {th('when', t('hist.col.when'), true)}
                  {th('title', t('hist.col.change'))}
                  {th('status', t('hist.col.status'))}
                  {th('ops', t('hist.col.ops'), true)}
                  <th>{t('hist.col.proof')}</th>
                  <th>{t('common.actions')}</th>
                </tr>
              )}
            >
              {(e) => {
                const key = `${String(e.changeset_id)}-${String(e.seq)}`;
                const statusKey = `dep.batch.${e.status}`;
                return (
                  <HistoryRow
                    key={key}
                    entry={e}
                    statusLabel={isMessageKey(statusKey) ? t(statusKey) : e.status}
                    open={open === key}
                    onToggle={() => {
                      setOpen(open === key ? null : key);
                    }}
                    actions={
                      approver && e.status === 'deployed' ? (
                        <>
                          {e.watch?.status === 'alert' && (
                            <button type="button" className="secondary" disabled={busy} onClick={() => void dismiss(e)}>
                              {t('watch.dismiss')}
                            </button>
                          )}
                          {e.revert_blocker === null && (
                            <button
                              type="button"
                              className="danger"
                              disabled={busy}
                              onClick={() =>
                                void post(
                                  `/api/changesets/${String(e.changeset_id)}/batches/${String(e.seq)}/revert`,
                                  t('hist.revertConfirm', { cs: e.changeset_id, title: e.title, seq: e.seq }),
                                )
                              }
                            >
                              {t('hist.revert')}
                            </button>
                          )}
                          {(e.revert_blocker === null || e.revert_blocker === 'later_batches_first') && (
                            <button
                              type="button"
                              className="secondary"
                              disabled={busy}
                              onClick={() =>
                                void post(
                                  '/api/history/revert-to',
                                  t('hist.revertToConfirm', { cs: e.changeset_id, title: e.title, seq: e.seq }),
                                  { changeset_id: e.changeset_id, seq: e.seq },
                                )
                              }
                            >
                              {t('hist.revertTo')}
                            </button>
                          )}
                          {e.revert_blocker !== null && e.revert_blocker !== 'later_batches_first' && (
                            <span className="muted small">
                              {isMessageKey(`hist.blocker.${e.revert_blocker}`)
                                ? t(`hist.blocker.${e.revert_blocker}` as MessageKey)
                                : e.revert_blocker}
                            </span>
                          )}
                        </>
                      ) : null
                    }
                  />
                );
              }}
            </SortedTable>
          </table>
        </section>
      )}
    </div>
  );
}

function HistoryRow({
  entry,
  statusLabel,
  open,
  onToggle,
  actions,
}: {
  entry: HistoryEntry;
  statusLabel: string;
  open: boolean;
  onToggle: () => void;
  actions: ReactNode;
}) {
  const { t } = useI18n();
  return (
    <>
      <tr className={open ? 'selected' : ''}>
        <td>
          <DateTime value={entry.finished_at ?? entry.started_at} />
        </td>
        <td>
          <button type="button" className="link" aria-expanded={open} onClick={onToggle}>
            <bdi>{entry.title}</bdi> · {t('dep.batch', { cs: entry.changeset_id, seq: entry.seq })}
          </button>
          <div className="muted small">
            <Ltr>{entry.ticket_id}</Ltr> · {t('hist.by', { author: entry.created_by, approver: entry.approved_by ?? '—' })}
          </div>
        </td>
        <td>
          <span className={`badge batch-badge batch-${entry.status}`}>{statusLabel}</span>
          {entry.error !== null && <div className="bad small">{entry.error}</div>}
          {entry.watch !== null && entry.watch !== undefined && entry.status === 'deployed' && <WatchState watch={entry.watch} />}
        </td>
        <td>{entry.op_count}</td>
        <td className="small">
          {entry.proof_after !== null ? (
            <span className={entry.proof_after.ok ? 'ok' : 'bad'}>
              {entry.proof_after.ok ? t('hist.proofOk', { flows: entry.proof_after.flows }) : t('hist.proofBad', { count: entry.proof_after.differences })}
            </span>
          ) : entry.proof !== null ? (
            <span className="muted">{t('hist.proofPlanned', { flows: entry.proof.flows, count: entry.proof.differences })}</span>
          ) : (
            <span className="muted">—</span>
          )}
        </td>
        <td className="actions">
          {entry.snapshot_id !== null && (
            <Link to={`/rules?snapshot=${String(entry.snapshot_id)}`} className="small">
              {t('hist.policyBefore')}
            </Link>
          )}
          {actions}
        </td>
      </tr>
      {open && (
        <tr className="history-detail">
          <td colSpan={6}>
            <ChangeList changesetId={entry.changeset_id} seq={entry.seq} />
          </td>
        </tr>
      )}
    </>
  );
}

function ChangeList({ changesetId, seq }: { changesetId: number; seq: number }) {
  const { t, tError } = useI18n();
  const changes = useApi<Change[]>(`/api/changesets/${String(changesetId)}/batches/${String(seq)}/changes`);
  if (changes.error !== null) return <Alert kind="error">{tError(changes.error)}</Alert>;
  if (changes.data === null) return <p className="muted small">{t('common.loading')}</p>;
  if (changes.data.length === 0) return <p className="muted small">{t('hist.noChanges')}</p>;
  return (
    <ul className="plain-list change-list">
      {changes.data.map((c, n) => (
        <li key={`${c.label}-${String(n)}`} className={`change change-${c.action}`}>
          <div>
            <span className={`badge change-badge change-${c.action}`}>{t(`hist.action.${c.action}`)}</span>{' '}
            <span className="muted small">{t(`hist.what.${c.what}`)}</span> <bdi>{c.label}</bdi>
            {c.undone && <span className="badge status-complete"> {t('hist.undone')}</span>}
          </div>
          {c.fields.length > 0 && (
            <table className="change-fields">
              <thead>
                <tr>
                  <th>{t('hist.field')}</th>
                  <th>{t('hist.before')}</th>
                  <th>{t('hist.after')}</th>
                </tr>
              </thead>
              <tbody>
                {c.fields.map((f) => (
                  <tr key={f.field}>
                    <td>
                      <Ltr>{f.field}</Ltr>
                    </td>
                    <td>
                      <del>
                        <bdi>{f.before ?? '—'}</bdi>
                      </del>
                    </td>
                    <td>
                      <ins>
                        <bdi>{f.after ?? '—'}</bdi>
                      </ins>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </li>
      ))}
    </ul>
  );
}

/** After-deploy watch of a batch: still watching, clean, or blocked traffic (with the rules). */
function WatchState({ watch }: { watch: Watch }) {
  const { t } = useI18n();
  if (watch.status === 'alert') {
    return (
      <div className="watch-state bad small" role="alert">
        <strong>{t('watch.alert')}</strong>
        <ul className="plain-list">
          {watch.alerts.map((a) => (
            <li key={a.id}>
              <bdi>{`#${String(a.index)} ${a.name}`}</bdi>: {t('watch.alertRule', { hits: a.new_hits, expected: Math.round(a.expected) })}
            </li>
          ))}
        </ul>
      </div>
    );
  }
  if (watch.status === 'watching') {
    return (
      <div className="watch-state muted small" title={t('watch.watchingHint')}>
        {t('watch.watching', { rules: watch.rules, blocks: watch.blocks })} <DateTime value={watch.until} />
        {watch.error !== null && <span className="bad"> · {t('watch.unreachable')}</span>}
      </div>
    );
  }
  if (watch.status === 'ok') return <div className="watch-state ok small">{t('watch.ok', { checks: watch.checks })}</div>;
  if (watch.status === 'dismissed') {
    return <div className="watch-state muted small">{t('watch.wasDismissed', { by: watch.dismissed_by ?? '—' })}</div>;
  }
  return null;
}
