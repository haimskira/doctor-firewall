import { useState } from 'react';
import type { SyntheticEvent } from 'react';
import { SortedTable } from '../components/sort';

import { api, errorCode } from '../api/client';
import { CONVENTION_KINDS } from '../api/types';
import type { ConventionCatalog, ConventionKind, NamingConvention, NamingStats } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { Alert, Ltr } from '../components/common';
import { useApi, useSnapshotSelection } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';

type Case = NamingConvention['letter_case'];
const CASES: readonly Case[] = ['upper', 'lower', 'keep'];

/** Admin-defined name templates per object kind (and for rules), with compliance figures. */
export function NamingPage() {
  const { t, tError } = useI18n();
  const { can } = useAuth();
  const catalog = useApi<ConventionCatalog>('/api/naming-conventions');
  const { snapshots } = useSnapshotSelection();
  const stats = new Map(Object.entries(snapshots.find((s) => s.analyzed_at !== null)?.stats.naming ?? {}));
  const tokens = new Map(Object.entries(catalog.data?.kinds ?? {}));
  const [notice, setNotice] = useState<string | null>(null);
  const editable = can('conventions:manage');
  const byKind = new Map((catalog.data?.conventions ?? []).map((c) => [c.kind, c]));

  return (
    <div className="stack">
      <div>
        <h1>{t('naming.title')}</h1>
        <p className="muted small">{t('naming.help')}</p>
      </div>
      {catalog.error !== null && <Alert kind="error">{tError(catalog.error)}</Alert>}
      {notice !== null && <Alert kind="success">{notice}</Alert>}
      {catalog.data !== null && (
        <section className="card">
          <table>
            <SortedTable
              rows={CONVENTION_KINDS}
              columns={{ kind: (kind) => kind, template: (kind) => byKind.get(kind)?.template, case: (kind) => byKind.get(kind)?.letter_case, enabled: (kind) => byKind.get(kind)?.enabled }}
              head={(th) => (
                <tr>
                  {th('kind', t('rec.col.kind'))}
                  {th('template', t('naming.template'))}
                  {th('case', t('naming.case'))}
                  {th('enabled', t('naming.enabled'))}
                  <th>{t('naming.tokens')}</th>
                  <th>{t('common.actions')}</th>
                </tr>
              )}
            >
              {(kind) => (
                <ConventionRow
                  key={`${kind}-${byKind.get(kind)?.updated_at ?? 'new'}`}
                  kind={kind}
                  current={byKind.get(kind) ?? null}
                  tokens={tokens.get(kind) ?? []}
                  stats={stats.get(kind)}
                  editable={editable}
                  onSaved={(message) => {
                    setNotice(message);
                    catalog.reload();
                  }}
                />
              )}
            </SortedTable>
          </table>
        </section>
      )}
    </div>
  );
}

function ConventionRow({
  kind,
  current,
  tokens,
  stats,
  editable,
  onSaved,
}: {
  kind: ConventionKind;
  current: NamingConvention | null;
  tokens: string[];
  stats: NamingStats | undefined;
  editable: boolean;
  onSaved: (message: string) => void;
}) {
  const { t, tError } = useI18n();
  const [template, setTemplate] = useState(current?.template ?? '');
  const [letterCase, setLetterCase] = useState<Case>(current?.letter_case ?? 'upper');
  const [enabled, setEnabled] = useState(current?.enabled ?? true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const label = t(`naming.kind.${kind}`);

  async function save(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api(`/api/naming-conventions/${kind}`, 'PUT', { template: template.trim(), letter_case: letterCase, enabled });
      onSaved(t('naming.saved'));
    } catch (err) {
      setError(errorCode(err));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setBusy(true);
    setError(null);
    try {
      await api(`/api/naming-conventions/${kind}`, 'DELETE');
      onSaved(t('naming.removed'));
    } catch (err) {
      setError(errorCode(err));
    } finally {
      setBusy(false);
    }
  }

  const formId = `naming-${kind}`;
  return (
    <tr>
      <td>
        <strong>{label}</strong>
        {stats !== undefined && current !== null && (
          <div className="muted small">
            {t('naming.stats', { compliant: stats.compliant, noncompliant: stats.noncompliant, proposed: stats.proposed })}
          </div>
        )}
        {current !== null && <div className="muted small">{t('naming.updated', { user: current.updated_by })}</div>}
        {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      </td>
      <td>
        {editable ? (
          <form id={formId} onSubmit={(e) => void save(e)}>
            <input
              dir="ltr"
              className="ltr"
              maxLength={128}
              aria-label={`${t('naming.template')} — ${label}`}
              placeholder={t('naming.notSet')}
              value={template}
              onChange={(e) => {
                setTemplate(e.target.value);
              }}
            />
          </form>
        ) : current !== null ? (
          <Ltr>{current.template}</Ltr>
        ) : (
          <span className="muted">{t('naming.notSet')}</span>
        )}
      </td>
      <td>
        {editable ? (
          <select
            form={formId}
            aria-label={`${t('naming.case')} — ${label}`}
            value={letterCase}
            onChange={(e) => {
              const next = CASES.find((c) => c === e.target.value);
              if (next !== undefined) setLetterCase(next);
            }}
          >
            {CASES.map((c) => (
              <option key={c} value={c}>
                {t(`naming.case.${c}`)}
              </option>
            ))}
          </select>
        ) : (
          current !== null && t(`naming.case.${current.letter_case}`)
        )}
      </td>
      <td>
        {editable ? (
          <input
            type="checkbox"
            form={formId}
            aria-label={`${t('naming.enabled')} — ${label}`}
            checked={enabled}
            onChange={(e) => {
              setEnabled(e.target.checked);
            }}
          />
        ) : (
          current !== null && (current.enabled ? t('common.yes') : t('common.no'))
        )}
      </td>
      <td>
        <span className="chips-inline">
          {tokens.map((tok) => (
            <code key={tok} className="chip small-chip">{`<${tok}>`}</code>
          ))}
        </span>
      </td>
      <td className="actions">
        {editable && (
          <>
            <button type="submit" form={formId} disabled={busy || template.trim() === ''}>
              {t('common.save')}
            </button>
            {current !== null && (
              <button type="button" className="danger" disabled={busy} onClick={() => void remove()}>
                {t('common.delete')}
              </button>
            )}
          </>
        )}
      </td>
    </tr>
  );
}
