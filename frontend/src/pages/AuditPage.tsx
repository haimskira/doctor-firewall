import { useCallback, useEffect, useState } from 'react';
import { SortedTable } from '../components/sort';

import { api, errorCode } from '../api/client';
import type { AuditRecord, AuditVerify } from '../api/types';
import { Alert, DateTime, Ltr } from '../components/common';
import { useI18n } from '../i18n/I18nProvider';

const PAGE = 100;

export function AuditPage() {
  const { t, tError } = useI18n();
  const [rows, setRows] = useState<AuditRecord[]>([]);
  const [beforeId, setBeforeId] = useState<number | null>(null);
  const [verify, setVerify] = useState<AuditVerify | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    (before: number | null) => {
      const query = before === null ? `?limit=${String(PAGE)}` : `?limit=${String(PAGE)}&before_id=${String(before)}`;
      api<AuditRecord[]>(`/api/audit${query}`)
        .then((data) => {
          setRows(data);
          setBeforeId(before);
        })
        .catch((err: unknown) => {
          setError(tError(errorCode(err)));
        });
    },
    [tError],
  );

  useEffect(() => {
    load(null);
  }, [load]);

  async function runVerify() {
    setError(null);
    try {
      setVerify(await api<AuditVerify>('/api/audit/verify', 'POST'));
    } catch (err: unknown) {
      setError(tError(errorCode(err)));
    }
  }

  const oldest = rows.at(-1);

  return (
    <div className="stack">
      <div className="row spread">
        <h1>{t('audit.title')}</h1>
        <button type="button" onClick={() => void runVerify()}>
          {t('audit.verify')}
        </button>
      </div>
      {error !== null && <Alert kind="error">{error}</Alert>}
      {verify?.ok === true && (
        <Alert kind="success">{t('audit.verifyOk', { count: verify.checked })}</Alert>
      )}
      {verify?.ok === false && (
        <Alert kind="error">
          {t('audit.verifyBroken', { id: verify.broken_at_id ?? '?', reason: verify.reason ?? '?' })}
        </Alert>
      )}
      <section className="card">
        <table>
          <SortedTable
            rows={rows}
            columns={{ ts: (row) => row.ts, actor: (row) => row.actor, action: (row) => row.action, outcome: (row) => row.outcome, target: (row) => row.target, source: (row) => row.source_ip }}
            head={(th) => (
              <tr>
                {th('ts', t('audit.time'), true)}
                {th('actor', t('audit.actor'))}
                {th('action', t('audit.action'))}
                {th('outcome', t('audit.outcome'))}
                {th('target', t('audit.target'))}
                {th('source', t('audit.source'))}
              </tr>
            )}
          >
            {(row) => (
              <tr key={row.id} className={`outcome-${row.outcome}`}>
                <td>
                  <DateTime value={row.ts} />
                </td>
                <td>
                  <Ltr>{row.actor}</Ltr>
                </td>
                <td>
                  <Ltr>{row.action}</Ltr>
                </td>
                <td>{row.outcome}</td>
                <td>
                  <Ltr>{row.target ?? ''}</Ltr>
                </td>
                <td>
                  <Ltr>{row.source_ip ?? ''}</Ltr>
                </td>
              </tr>
            )}
          </SortedTable>
        </table>
        <div className="row">
          <button
            type="button"
            className="secondary"
            disabled={beforeId === null}
            onClick={() => {
              load(null);
            }}
          >
            {t('audit.newest')}
          </button>
          <button
            type="button"
            className="secondary"
            disabled={oldest === undefined || rows.length < PAGE}
            onClick={() => {
              if (oldest !== undefined) load(oldest.id);
            }}
          >
            {t('audit.older')}
          </button>
        </div>
      </section>
    </div>
  );
}
