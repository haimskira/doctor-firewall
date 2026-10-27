import { useState } from 'react';
import type { SyntheticEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { api, errorCode } from '../api/client';
import { RECOMMENDATION_KINDS } from '../api/types';
import type { Recommendation, RecommendationDetail, RecommendationsPage as Page } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { Alert, Ltr } from '../components/common';
import { SnapshotPicker } from '../components/inventory';
import { RecommendationPreviewView, signed, tagGroup } from '../components/recommendations';
import { useJobs } from '../components/jobs';
import { isAhead, isPhase } from '../components/roadmap';
import type { Roadmap } from '../components/roadmap';
import { SortTh, useServerSort } from '../components/sort';
import type { SortState } from '../components/sort';
import { useApi, useQueryParam, useSnapshotSelection } from '../hooks';
import { isMessageKey, useI18n } from '../i18n/I18nProvider';
import type { MessageKey } from '../i18n/messages';
import { useOpLabel } from './DeployPage';

const PAGE_SIZE = 100;
// A changeset holds at most this many recommendations (server limit); the highest priority first.
const STAGE_MAX = 500;
const SORTS = ['priority', 'title', 'ace_delta', 'deploy_cost'] as const;
const STATES = ['open', 'accepted', 'dismissed'] as const;

/**
 * The recommendation queue (highest priority first) with a preview pane: inline or
 * before/after diff, impact and deploy cost, and the (local) accept / dismiss decision.
 */
export function RecommendationsPage() {
  const { t, tError } = useI18n();
  const { can } = useAuth();
  const { snapshots, snapshotId, setSnapshotId, error: snapError } = useSnapshotSelection();
  const [kind, setKind] = useQueryParam('kind');
  const [state, setState] = useQueryParam('state');
  const [rule] = useQueryParam('rule');
  const [recParam, setRecParam] = useQueryParam('rec');
  const [phaseParam, setPhase] = useQueryParam('phase');
  const phase = isPhase(phaseParam) ? phaseParam : null;
  const [offset, setOffset] = useState(0);
  const jobs = useJobs();
  const sort = useServerSort(SORTS);
  const onSort = (next: SortState) => {
    sort.onSort(next);
    setOffset(0);
  };
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset) });
  if (kind !== null) params.set('kind', kind);
  if (state !== null) params.set('state', state);
  if (rule !== null) params.set('rule', rule);
  if (phase !== null) params.set('phase', phase);
  for (const [k, v] of Object.entries(sort.query)) params.set(k, v);
  const base = snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}/recommendations`;
  const page = useApi<Page>(base === null ? null : `${base}?${params.toString()}`);
  const selectedId = recParam !== null && /^\d+$/.test(recParam) ? Number(recParam) : null;
  const detail = useApi<RecommendationDetail>(base === null || selectedId === null ? null : `${base}/${String(selectedId)}`);
  const roadmap = useApi<Roadmap>(base === null ? null : `/api/snapshots/${String(snapshotId)}/roadmap`);
  const error = snapError ?? page.error;

  function filter(setter: (v: string | null) => void, value: string | null) {
    setter(value);
    setOffset(0);
  }

  async function reanalyze() {
    if (snapshotId === null) return;
    setActionError(null);
    try {
      await api(`/api/snapshots/${String(snapshotId)}/analyze`, 'POST');
      setNotice(t('rec.reanalyzeQueued'));
      jobs.kick();
    } catch (err) {
      setActionError(errorCode(err));
    }
  }

  const summary = new Map(Object.entries(page.data?.summary ?? {}));
  const accepted = page.data?.accepted;

  return (
    <div className="stack">
      <div className="row spread">
        <div>
          <h1>{t('rec.title')}</h1>
          <p className="muted small">{t('rec.help')}</p>
        </div>
        <div className="row">
          <SnapshotPicker snapshots={snapshots} value={snapshotId} onChange={setSnapshotId} />
          {can('collect:run') && snapshotId !== null && (
            <button type="button" className="secondary" onClick={() => void reanalyze()}>
              {t('rec.reanalyze')}
            </button>
          )}
        </div>
      </div>
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      {actionError !== null && <Alert kind="error">{tError(actionError)}</Alert>}
      {notice !== null && <Alert kind="success">{notice}</Alert>}
      {snapshotId === null && snapError === null && <Alert kind="info">{t('snap.none')}</Alert>}

      {page.data?.stale != null && (
        <Alert kind="error">
          {t('rec.stale', { changeset: page.data.stale.changeset_id, batch: page.data.stale.batch, at: new Date(page.data.stale.at).toLocaleString() })}{' '}
          <Link to="/snapshots">{t('rec.staleAction')}</Link>
        </Alert>
      )}
      {phase !== null && (
        <Alert kind="info">
          {t('road.filtered', { phase: t(`road.phase.${phase}`) })}{' '}
          <Link to={`/roadmap?snapshot=${String(snapshotId ?? '')}`}>{t('road.back')}</Link>{' '}
          <button
            type="button"
            className="link"
            onClick={() => {
              filter(setPhase, null);
            }}
          >
            {t('road.clear')}
          </button>
        </Alert>
      )}
      {page.data !== null && (
        <>
          <div className="rec-summary" role="group" aria-label={t('rec.col.kind')}>
            <button
              type="button"
              className={kind === null ? 'rec-kind active' : 'rec-kind'}
              onClick={() => {
                filter(setKind, null);
              }}
            >
              <span>{t('rec.all')}</span>
            </button>
            {RECOMMENDATION_KINDS.filter((k) => (summary.get(k)?.count ?? 0) > 0).map((k) => (
              <button
                key={k}
                type="button"
                className={`rec-kind tag-${tagGroup(k)}${kind === k ? ' active' : ''}`}
                onClick={() => {
                  filter(setKind, k);
                }}
              >
                <span>{t(`rec.kind.${k}`)}</span>
                <strong>{summary.get(k)?.count ?? 0}</strong>
                <span className="muted small">{t('rec.cost', { count: summary.get(k)?.deploy_cost ?? 0 })}</span>
              </button>
            ))}
          </div>
          <div className="rec-toolbar card-toolbar">
            <label className="inline-field">
              {t('rec.col.state')}
              <select
                value={state ?? ''}
                onChange={(e) => {
                  filter(setState, e.target.value === '' ? null : e.target.value);
                }}
              >
                <option value="">{t('rec.all')}</option>
                {STATES.map((s) => (
                  <option key={s} value={s}>
                    {t(`rec.state.${s}`)}
                  </option>
                ))}
              </select>
            </label>
            {can('changeset:write') && snapshotId !== null && page.data.stale == null && (
              <BulkDecision
                snapshotId={snapshotId}
                filter={{ kind, rule, phase }}
                acceptedView={state === 'accepted'}
                onDone={(message) => {
                  setNotice(message);
                  page.reload();
                }}
              />
            )}
            {accepted !== undefined && (
              <span className="rec-toolbar-summary">
                {t('rec.acceptedSummary', {
                  count: accepted.count,
                  cost: accepted.deploy_cost,
                  ace: signed(accepted.ace_delta),
                })}
                {page.data.accepted_staged > 0 && (
                  <span className="rec-staged-note">
                    {t('rec.stagedNote', { count: page.data.accepted_staged })}{' '}
                    {page.data.staged_changesets.map((c) => (
                      <Link key={c.id} to={`/deploy?changeset=${String(c.id)}`}>
                        #{c.id} <bdi>{c.title}</bdi>
                      </Link>
                    ))}
                  </span>
                )}
              </span>
            )}
            {accepted !== undefined && accepted.count > page.data.accepted_staged && can('changeset:write') && snapshotId !== null && (
              <StageForm snapshotId={snapshotId} accepted={accepted.count - page.data.accepted_staged} />
            )}
          </div>

          <div className="rec-layout">
            <section className="card rec-list">
              {page.data.rows.length === 0 ? (
                <p className="muted">{t('rec.none')}</p>
              ) : (
                <table>
                  <thead>
                    <tr>
                      <SortTh label={t('rec.col.priority')} sortKey="priority" state={sort.state} onSort={onSort} numeric />
                      <SortTh label={t('rec.col.title')} sortKey="title" state={sort.state} onSort={onSort} />
                      <SortTh label={t('rec.col.impact')} sortKey="ace_delta" state={sort.state} onSort={onSort} numeric />
                      <SortTh label={t('rec.col.cost')} sortKey="deploy_cost" state={sort.state} onSort={onSort} numeric />
                      <th>{t('rec.col.state')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {page.data.rows.map((r) => (
                      <RecRow
                        key={r.id}
                        rec={r}
                        selected={r.id === selectedId}
                        onSelect={() => {
                          setRecParam(String(r.id));
                        }}
                      />
                    ))}
                  </tbody>
                </table>
              )}
              <div className="row spread">
                <button
                  type="button"
                  className="secondary"
                  disabled={offset === 0}
                  onClick={() => {
                    setOffset(Math.max(0, offset - PAGE_SIZE));
                  }}
                >
                  ‹
                </button>
                <span className="muted small">
                  {page.data.total === 0 ? 0 : offset + 1}–{offset + page.data.rows.length} / {page.data.total}
                </span>
                <button
                  type="button"
                  className="secondary"
                  disabled={offset + PAGE_SIZE >= page.data.total}
                  onClick={() => {
                    setOffset(offset + PAGE_SIZE);
                  }}
                >
                  ›
                </button>
              </div>
            </section>
            <section className="card rec-detail" aria-live="polite">
              {detail.error !== null && <Alert kind="error">{tError(detail.error)}</Alert>}
              {detail.data === null || snapshotId === null ? (
                <p className="muted">{t('rec.select')}</p>
              ) : (
                <Detail
                  key={`${String(detail.data.id)}-${detail.data.decision?.status ?? 'open'}`}
                  rec={detail.data}
                  snapshotId={snapshotId}
                  canDecide={can('changeset:write')}
                  currentPhase={roadmap.data?.current ?? null}
                  onDecided={() => {
                    detail.reload();
                    page.reload();
                  }}
                />
              )}
            </section>
          </div>
        </>
      )}
    </div>
  );
}

/** A server-provided code: translated when known, shown raw (LTR) otherwise. */
function Known({ code, raw }: { code: string; raw: string }) {
  const { t } = useI18n();
  return isMessageKey(code) ? <>{t(code)}</> : <Ltr>{raw}</Ltr>;
}

function Impact({ rec }: { rec: Recommendation }) {
  const { t } = useI18n();
  return (
    <span className="rec-impact">
      {rec.ace_delta !== 0 && (
        <span className={rec.ace_delta < 0 ? 'ok' : 'bad'}>{t('rec.ace', { delta: signed(rec.ace_delta) })}</span>
      )}
      {rec.score_delta !== null && rec.score_delta !== 0 && (
        <span className={rec.score_delta > 0 ? 'ok' : 'bad'}>{t('rec.score', { delta: signed(rec.score_delta) })}</span>
      )}
    </span>
  );
}

function RecRow({ rec, selected, onSelect }: { rec: Recommendation; selected: boolean; onSelect: () => void }) {
  const { t } = useI18n();
  return (
    <tr className={selected ? 'selected' : ''}>
      <td>{rec.priority}</td>
      <td>
        <span className={`rec-tag tag-${tagGroup(rec.kind)}`}>{t(`rec.kind.${rec.kind}`)}</span>{' '}
        <button type="button" className="link finding-title" aria-pressed={selected} onClick={onSelect}>
          <bdi>{rec.title}</bdi>
        </button>
        {rec.behavior === 'changes' && (
          <span className="badge behavior-changes" title={t('rec.behavior.changesHint')}>
            {t('rec.behavior.changes')}
          </span>
        )}
      </td>
      <td>
        <Impact rec={rec} />
      </td>
      <td>{rec.deploy_cost}</td>
      <td>
        {rec.applied === true ? (
          <span className="badge status-complete">{t('rec.state.applied')}</span>
        ) : rec.decision === null ? (
          t('rec.state.open')
        ) : (
          t(`rec.state.${rec.decision.status}`)
        )}
      </td>
    </tr>
  );
}

function Detail({
  rec,
  snapshotId,
  canDecide,
  currentPhase,
  onDecided,
}: {
  rec: RecommendationDetail;
  snapshotId: number;
  canDecide: boolean;
  currentPhase: string | null;
  onDecided: () => void;
}) {
  const { t, tError } = useI18n();
  const hasRules = (rec.preview.after?.length ?? 0) > 0;
  const opLabel = useOpLabel();
  const [view, setView] = useState<'inline' | 'split'>(rec.display);
  const [note, setNote] = useState(rec.decision?.note ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function decide(status: 'accepted' | 'dismissed' | 'open') {
    setBusy(true);
    setError(null);
    try {
      await api(`/api/snapshots/${String(snapshotId)}/recommendations/${String(rec.id)}/decision`, 'PUT', {
        status,
        note: note.trim(),
      });
      onDecided();
    } catch (err) {
      setError(errorCode(err));
    } finally {
      setBusy(false);
    }
  }

  function onSubmit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    void decide('accepted');
  }

  return (
    <div className="stack">
      <div>
        <span className={`rec-tag tag-${tagGroup(rec.kind)}`}>{t(`rec.kind.${rec.kind}`)}</span>
        <h2>
          <bdi>{rec.title}</bdi>
        </h2>
        <div className="rec-facts small">
          <span>
            <span className="muted">{t('rec.principleLabel')}: </span>
            <Known code={`rec.principle.${rec.principle}`} raw={rec.principle} />
          </span>
          <span>
            <span className="muted">{t('rec.col.cost')}: </span>
            {rec.deploy_cost}
          </span>
          <Impact rec={rec} />
          {rec.preview.policy !== undefined && (
            <span className="muted">
              <Ltr>{rec.preview.policy.name}</Ltr>
            </span>
          )}
        </div>
      </div>
      {rec.decision === null && isPhase(currentPhase) && isAhead(rec.kind, currentPhase) && (
        <Alert kind="warning">
          {t('road.ahead', { phase: t(`road.phase.${currentPhase}`) })}{' '}
          <Link to={`/roadmap?snapshot=${String(snapshotId)}`}>{t('road.back')}</Link>
        </Alert>
      )}
      {!rec.executable && (
        <div className="alert alert-error" role="note">
          <strong>{t('rec.notExecutable')}</strong>
          <ul>
            {rec.blocked.map((b) => (
              <li key={b}>
                <Known code={`rec.blocked.${b}`} raw={b} />
              </li>
            ))}
          </ul>
        </div>
      )}
      {rec.warnings.length > 0 && (
        <div className="alert alert-info" role="note">
          <strong>{t('rec.warnings')}</strong>
          <ul>
            {rec.warnings.map((w) => (
              <li key={w}>
                <Known code={`rec.warning.${w}`} raw={w} />
              </li>
            ))}
          </ul>
        </div>
      )}
      {hasRules && (
        <div className="segmented" role="group" aria-label={t('rec.view')}>
          {(['inline', 'split'] as const).map((v) => (
            <button
              key={v}
              type="button"
              className={view === v ? '' : 'secondary'}
              aria-pressed={view === v}
              onClick={() => {
                setView(v);
              }}
            >
              {t(`rec.view.${v}`)}
            </button>
          ))}
        </div>
      )}
      <RecommendationPreviewView preview={rec.preview} view={view} snapshotId={snapshotId} />
      {(rec.plan.ops ?? []).length > 0 && (
        <section>
          <h3>{t('rec.plan')}</h3>
          <ol className="small ops-list">
            {(rec.plan.ops ?? []).map((op, n) => (
              <li key={`${op.op}-${String(n)}`}>
                <Ltr>{opLabel(op)}</Ltr>
              </li>
            ))}
          </ol>
        </section>
      )}

      {rec.decision !== null && (
        <p className="muted small">
          {t('rec.decidedBy', { status: t(`rec.state.${rec.decision.status}`), user: rec.decision.decided_by })}
          {rec.decision.note !== '' && (
            <>
              {' · '}
              <bdi>{rec.decision.note}</bdi>
            </>
          )}
        </p>
      )}
      {canDecide && (
        <form className="stack" onSubmit={onSubmit}>
          {error !== null && <Alert kind="error">{tError(error)}</Alert>}
          <label>
            {t('rec.note')}
            <input
              dir="auto"
              maxLength={512}
              value={note}
              onChange={(e) => {
                setNote(e.target.value);
              }}
            />
          </label>
          <div className="row">
            <button type="submit" disabled={busy || rec.decision?.status === 'accepted'}>
              {t('rec.accept')}
            </button>
            <button
              type="button"
              className="secondary"
              disabled={busy || rec.decision?.status === 'dismissed'}
              onClick={() => void decide('dismissed')}
            >
              {t('rec.dismiss')}
            </button>
            {rec.decision !== null && (
              <button type="button" className="secondary" disabled={busy} onClick={() => void decide('open')}>
                {t('rec.reopen')}
              </button>
            )}
          </div>
          <p className="muted small">{t('rec.local')}</p>
        </form>
      )}
    </div>
  );
}

interface BulkResult {
  changing: number;
  count: number;
  deploy_cost: number;
  ace_delta: number;
  skipped: Record<string, number>;
  deploy_limit: number;
  batches: number;
}

/** Accept every open recommendation the list shows (its kind / rule filter), or reopen the
    accepted ones — after a preview of how many, how many FMC changes and deploy batches. */
function BulkDecision({
  snapshotId,
  filter,
  acceptedView,
  onDone,
}: {
  snapshotId: number;
  filter: { kind: string | null; rule: string | null; phase: string | null };
  acceptedView: boolean;
  onDone: (message: string) => void;
}) {
  const { t, tError } = useI18n();
  const [preview, setPreview] = useState<{ status: 'accepted' | 'open'; result: BulkResult } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const url = `/api/snapshots/${String(snapshotId)}/recommendations/decisions`;
  const scope = {
    ...(filter.kind === null ? {} : { kind: filter.kind }),
    ...(filter.rule === null ? {} : { rule: filter.rule }),
    ...(filter.phase === null ? {} : { phase: filter.phase }),
  };
  const what =
    filter.kind !== null
      ? t(`rec.kind.${filter.kind}` as MessageKey)
      : isPhase(filter.phase)
        ? t(`road.phase.${filter.phase}`)
        : t('rec.bulk.everything');

  async function ask(status: 'accepted' | 'open') {
    setBusy(true);
    setError(null);
    try {
      const result = await api<BulkResult>(url, 'POST', { status, ...scope, dry_run: true });
      setAcknowledged(false);
      setPreview({ status, result });
    } catch (err) {
      setError(errorCode(err));
    } finally {
      setBusy(false);
    }
  }

  async function confirm() {
    if (preview === null) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api<BulkResult>(url, 'POST', {
        status: preview.status,
        ...scope,
        ...(preview.result.changing > 0 ? { acknowledge_change: acknowledged } : {}),
      });
      setPreview(null);
      onDone(t(preview.status === 'accepted' ? 'rec.bulk.accepted' : 'rec.bulk.reopened', { count: result.count }));
    } catch (err) {
      setError(errorCode(err));
    } finally {
      setBusy(false);
    }
  }

  const skipped = preview === null ? 0 : Object.values(preview.result.skipped).reduce((a, b) => a + b, 0);
  return (
    <>
      {preview === null ? (
        <>
          {!acceptedView && (
            <button type="button" disabled={busy} onClick={() => void ask('accepted')}>
              {t('rec.bulk.accept', { what })}
            </button>
          )}
          {acceptedView && (
            <button type="button" className="secondary" disabled={busy} onClick={() => void ask('open')}>
              {t('rec.bulk.reopen', { what })}
            </button>
          )}
        </>
      ) : (
        <div className="toolbar-panel bulk-confirm" role="dialog" aria-label={t('rec.bulk.confirmTitle')}>
          {preview.result.count === 0 ? (
            <p>{t('rec.bulk.nothing')}</p>
          ) : preview.status === 'accepted' ? (
            <p>
              {t('rec.bulk.previewAccept', {
                count: preview.result.count,
                what,
                cost: preview.result.deploy_cost,
                batches: preview.result.batches,
                limit: preview.result.deploy_limit,
              })}
            </p>
          ) : (
            <p>{t('rec.bulk.previewReopen', { count: preview.result.count, what })}</p>
          )}
          {skipped > 0 && (
            <p className="muted small">
              {t('rec.bulk.skipped', {
                count: skipped,
                blocked: preview.result.skipped['not_executable'] ?? 0,
                staged: preview.result.skipped['already_staged'] ?? 0,
                changing: preview.result.skipped['changes_behavior'] ?? 0,
              })}
            </p>
          )}
          {preview.result.changing > 0 && (
            <div className="behavior-warning">
              <p>
                <strong>{t('rec.bulk.changingTitle', { count: preview.result.changing })}</strong> {t('rec.bulk.changingText')}
              </p>
              <label className="inline-field">
                <input
                  type="checkbox"
                  checked={acknowledged}
                  onChange={(e) => {
                    setAcknowledged(e.target.checked);
                  }}
                />
                {t('rec.bulk.acknowledge')}
              </label>
            </div>
          )}
          <p className="muted small">{t('rec.bulk.safety')}</p>
          <div className="row">
            {preview.result.count > 0 && (
              <button type="button" disabled={busy || (preview.result.changing > 0 && !acknowledged)} onClick={() => void confirm()}>
                {t(preview.status === 'accepted' ? 'rec.bulk.confirmAccept' : 'rec.bulk.confirmReopen', { count: preview.result.count })}
              </button>
            )}
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => {
                setPreview(null);
              }}
            >
              {t('common.cancel')}
            </button>
          </div>
        </div>
      )}
      {error !== null && (
        <div className="toolbar-panel">
          <Alert kind="error">{tError(error)}</Alert>
        </div>
      )}
    </>
  );
}

/** Stage every accepted recommendation of the snapshot into a new changeset (local only). */
function StageForm({ snapshotId, accepted }: { snapshotId: number; accepted: number }) {
  const { t, tError } = useI18n();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState('');
  const [ticket, setTicket] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const page = await api<Page>(
        `/api/snapshots/${String(snapshotId)}/recommendations?state=accepted&unstaged=true&limit=${String(STAGE_MAX)}`,
      );
      if (page.rows.length === 0) {
        setError('nothing_to_stage');
        return;
      }
      const made = await api<{ id: number }>('/api/changesets', 'POST', {
        snapshot_id: snapshotId,
        recommendation_ids: page.rows.map((r) => r.id),
        title: title.trim(),
        ticket_id: ticket.trim(),
      });
      void navigate(`/deploy?changeset=${String(made.id)}`);
    } catch (err) {
      setError(errorCode(err));
    } finally {
      setBusy(false);
    }
  }

  if (!open) {
    return (
      <button
        type="button"
        className="rec-toolbar-primary"
        onClick={() => {
          setOpen(true);
        }}
      >
        {t('dep.stage')}
      </button>
    );
  }
  return (
    <form className="toolbar-panel stage-form" onSubmit={(e) => void submit(e)}>
      {accepted > STAGE_MAX && <p className="muted small grow">{t('dep.stageCapped', { count: accepted, max: STAGE_MAX })}</p>}
      <label className="inline-field">
        {t('dep.stageTitle')}
        <input
          dir="auto"
          required
          minLength={3}
          maxLength={200}
          value={title}
          onChange={(e) => {
            setTitle(e.target.value);
          }}
        />
      </label>
      <label className="inline-field">
        {t('dep.stageTicket')}
        <input
          dir="ltr"
          className="ltr"
          required
          pattern="[A-Za-z0-9][A-Za-z0-9._/\-]{1,63}"
          maxLength={64}
          value={ticket}
          onChange={(e) => {
            setTicket(e.target.value);
          }}
        />
      </label>
      <button type="submit" disabled={busy}>
        {t('dep.stageCreate')}
      </button>
      <button
        type="button"
        className="secondary"
        onClick={() => {
          setOpen(false);
        }}
      >
        {t('common.cancel')}
      </button>
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
    </form>
  );
}
