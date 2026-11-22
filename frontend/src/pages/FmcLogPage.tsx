import { useState } from 'react';
import { Link } from 'react-router-dom';

import { Alert, Ltr } from '../components/common';
import { useApi, useQueryParam, useSetQueryParams } from '../hooks';
import { isMessageKey, useI18n } from '../i18n/I18nProvider';

export interface FmcEvent {
  id: number;
  at: string;
  op_id: string;
  operation: string;
  connection_id: number | null;
  connection_name: string;
  snapshot_id: number | null;
  batch_id: number | null;
  run_id: number | null;
  step: string;
  kind: 'started' | 'request' | 'failed' | 'finished';
  outcome: 'ok' | 'error';
  method: string;
  path: string;
  status: number | null;
  duration_ms: number | null;
  error_code: string;
  detail: string;
  response: string;
}

interface Page {
  total: number;
  offset: number;
  rows: FmcEvent[];
}

const OPERATIONS = ['collect', 'test', 'batch', 'revert', 'rollback', 'watch'] as const;
const PAGE = 100;

function duration(ms: number | null): string {
  if (ms === null) return '';
  if (ms < 1000) return `${String(ms)}ms`;
  const s = ms / 1000;
  return s < 120 ? `${s.toFixed(1)}s` : `${String(Math.round(s / 60))}m`;
}

/** The FMC integration log: every operation against the FMC and every request it made. */
export function FmcLogPage() {
  const [op] = useQueryParam('op');
  return op === null ? <Operations /> : <OperationDetail op={op} />;
}

function useLabels() {
  const { t } = useI18n();
  return {
    operation(name: string): string {
      const key = `fmclog.op.${name}`;
      return isMessageKey(key) ? t(key) : name;
    },
    when(at: string): string {
      return new Date(at).toLocaleString();
    },
  };
}

function Operations() {
  const { t, tError } = useI18n();
  const labels = useLabels();
  const setParams = useSetQueryParams();
  const [operation] = useQueryParam('operation');
  const [outcome] = useQueryParam('outcome');
  const [snapshot] = useQueryParam('snapshot_id');
  const [batch] = useQueryParam('batch_id');
  const [q, setQ] = useQueryParam('q');
  const [draft, setDraft] = useState(q ?? '');
  const [limit, setLimit] = useState(PAGE);

  const params = new URLSearchParams({ kind: 'finished', limit: String(limit) });
  if (operation !== null) params.set('operation', operation);
  if (outcome !== null) params.set('outcome', outcome);
  if (snapshot !== null) params.set('snapshot_id', snapshot);
  if (batch !== null) params.set('batch_id', batch);
  if (q !== null) params.set('q', q);
  const page = useApi<Page>(`/api/fmc/events?${params.toString()}`);
  const rows = page.data?.rows ?? [];
  const exportParams = new URLSearchParams(params);
  exportParams.delete('kind');
  exportParams.delete('limit');

  return (
    <div className="stack">
      <div className="row spread">
        <h1>{t('fmclog.title')}</h1>
        <a className="button-link" href={`/api/fmc/events/export?${exportParams.toString()}`} download>
          {t('fmclog.export')}
        </a>
      </div>
      <p className="muted">{t('fmclog.help')}</p>
      {(snapshot !== null || batch !== null) && (
        <Alert kind="info">
          {snapshot !== null ? t('fmclog.forSnapshot', { id: snapshot }) : t('fmclog.forBatch', { id: batch ?? '' })}{' '}
          <button
            type="button"
            className="link"
            onClick={() => {
              setParams({ snapshot_id: null, batch_id: null });
            }}
          >
            {t('fmclog.showAll')}
          </button>
        </Alert>
      )}
      <form
        className="row fmclog-filters"
        onSubmit={(e) => {
          e.preventDefault();
          setQ(draft.trim() === '' ? null : draft.trim());
        }}
      >
        <label className="inline-field">
          {t('fmclog.operation')}
          <select
            value={operation ?? ''}
            onChange={(e) => {
              setParams({ operation: e.target.value === '' ? null : e.target.value });
            }}
          >
            <option value="">{t('fmclog.all')}</option>
            {OPERATIONS.map((o) => (
              <option key={o} value={o}>
                {labels.operation(o)}
              </option>
            ))}
          </select>
        </label>
        <div className="segmented" role="group" aria-label={t('fmclog.outcome')}>
          {([null, 'error'] as const).map((o) => (
            <button
              key={o ?? 'all'}
              type="button"
              className={outcome === o ? 'active' : ''}
              aria-pressed={outcome === o}
              onClick={() => {
                setParams({ outcome: o });
              }}
            >
              {o === null ? t('fmclog.all') : t('fmclog.failedOnly')}
            </button>
          ))}
        </div>
        <input
          type="search"
          dir="auto"
          maxLength={128}
          className="grow"
          aria-label={t('fmclog.search')}
          placeholder={t('fmclog.search')}
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value);
          }}
        />
        <button type="submit" className="secondary">
          {t('common.search')}
        </button>
      </form>
      {page.error !== null && <Alert kind="error">{tError(page.error)}</Alert>}
      {page.data !== null && rows.length === 0 && <Alert kind="info">{t('fmclog.empty')}</Alert>}
      {rows.length > 0 && (
        <section className="card">
          <table>
            <thead>
              <tr>
                <th>{t('fmclog.col.when')}</th>
                <th>{t('fmclog.operation')}</th>
                <th>{t('fmclog.col.connection')}</th>
                <th>{t('fmclog.col.subject')}</th>
                <th>{t('fmclog.outcome')}</th>
                <th>{t('fmclog.col.duration')}</th>
                <th>{t('fmclog.col.requests')}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className={r.outcome === 'error' ? 'fmclog-row-error' : ''}>
                  <td className="nowrap">{labels.when(r.at)}</td>
                  <td>{labels.operation(r.operation)}</td>
                  <td>{r.connection_name}</td>
                  <td>
                    {r.snapshot_id !== null && <span>{t('fmclog.snapshot', { id: r.snapshot_id })} </span>}
                    {r.batch_id !== null && <span>{t('fmclog.batch', { id: r.batch_id })}</span>}
                  </td>
                  <td>
                    <span className={`badge fmclog-${r.outcome}`}>
                      {r.outcome === 'ok' ? t('fmclog.ok') : t('fmclog.failed')}
                    </span>
                  </td>
                  <td>{duration(r.duration_ms)}</td>
                  <td className="small">
                    <Ltr>{r.detail}</Ltr>
                  </td>
                  <td>
                    <Link to={`/fmc-log?op=${r.op_id}`}>{t('fmclog.details')}</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {page.data !== null && page.data.total > rows.length && (
            <button
              type="button"
              className="secondary"
              onClick={() => {
                setLimit((n) => Math.min(n + PAGE, 500));
              }}
              disabled={limit >= 500}
            >
              {t('common.loadMore')}
            </button>
          )}
        </section>
      )}
    </div>
  );
}

function OperationDetail({ op }: { op: string }) {
  const { t, tError } = useI18n();
  const labels = useLabels();
  const setParams = useSetQueryParams();
  const [errorsOnly, setErrorsOnly] = useState(false);
  const [open, setOpen] = useState<number | null>(null);
  const params = new URLSearchParams({ op, limit: '500' });
  if (errorsOnly) params.set('outcome', 'error');
  const page = useApi<Page>(`/api/fmc/events?${params.toString()}`);
  const events = [...(page.data?.rows ?? [])].reverse(); // oldest first: read it as it happened
  const head = events.find((e) => e.kind === 'started') ?? events.at(0);
  const end = events.find((e) => e.kind === 'finished');
  const failure = events.find((e) => e.kind === 'failed');

  return (
    <div className="stack">
      <div className="row spread">
        <h1>{t('fmclog.title')}</h1>
        <div className="row">
          <a className="button-link" href={`/api/fmc/events/export?op=${op}`} download>
            {t('fmclog.export')}
          </a>
          <button
            type="button"
            className="secondary"
            onClick={() => {
              setParams({ op: null });
            }}
          >
            {t('fmclog.back')}
          </button>
        </div>
      </div>
      {page.error !== null && <Alert kind="error">{tError(page.error)}</Alert>}
      {head !== undefined && (
        <section className="card fmclog-summary">
          <div>
            <strong>{labels.operation(head.operation)}</strong> · {head.connection_name}
            {head.snapshot_id !== null && <> · {t('fmclog.snapshot', { id: head.snapshot_id })}</>}
            {head.batch_id !== null && <> · {t('fmclog.batch', { id: head.batch_id })}</>}
          </div>
          <div className="muted small">
            {labels.when(head.at)}
            {end !== undefined && <> · {duration(end.duration_ms)} · <Ltr>{end.detail}</Ltr></>}
          </div>
          {failure !== undefined && (
            <Alert kind="error">
              <div>
                <strong>{t('fmclog.failedAt', { step: failure.step || '—' })}</strong>
              </div>
              <div>{tError(failure.error_code)}</div>
              <pre className="fmclog-pre" dir="ltr">
                {failure.detail}
              </pre>
            </Alert>
          )}
        </section>
      )}
      <label className="inline">
        <input
          type="checkbox"
          checked={errorsOnly}
          onChange={(e) => {
            setErrorsOnly(e.target.checked);
          }}
        />
        {t('fmclog.failedOnly')}
      </label>
      {page.data !== null && page.data.total > 500 && <p className="muted small">{t('fmclog.capped')}</p>}
      <section className="card">
        <table className="fmclog-events">
          <thead>
            <tr>
              <th>{t('fmclog.col.when')}</th>
              <th>{t('fmclog.col.step')}</th>
              <th>{t('fmclog.col.request')}</th>
              <th>{t('fmclog.col.status')}</th>
              <th>{t('fmclog.col.duration')}</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => {
              const expandable = e.detail !== '' || e.response !== '';
              const isOpen = open === e.id;
              return [
                <tr
                  key={e.id}
                  className={`${e.outcome === 'error' ? 'fmclog-row-error' : ''}${expandable ? ' fmclog-expandable' : ''}`}
                  onClick={() => {
                    if (expandable) setOpen(isOpen ? null : e.id);
                  }}
                >
                  <td className="nowrap small">{new Date(e.at).toLocaleTimeString()}</td>
                  <td className="small">{e.step}</td>
                  <td className="small">
                    {e.kind === 'request' ? (
                      <Ltr>
                        {e.method} {e.path}
                      </Ltr>
                    ) : (
                      <strong>{t(`fmclog.kind.${e.kind}`)}</strong>
                    )}
                  </td>
                  <td className="small">
                    <Ltr>{e.status ?? e.error_code}</Ltr>
                  </td>
                  <td className="small">{duration(e.duration_ms)}</td>
                </tr>,
                isOpen && (
                  <tr key={`${String(e.id)}-more`} className="fmclog-more">
                    <td colSpan={5}>
                      {e.detail !== '' && (
                        <pre className="fmclog-pre" dir="ltr">
                          {e.detail}
                        </pre>
                      )}
                      {e.response !== '' && (
                        <>
                          <div className="muted small">{t('fmclog.response')}</div>
                          <pre className="fmclog-pre" dir="ltr">
                            {e.response}
                          </pre>
                        </>
                      )}
                    </td>
                  </tr>
                ),
              ];
            })}
          </tbody>
        </table>
      </section>
    </div>
  );
}
