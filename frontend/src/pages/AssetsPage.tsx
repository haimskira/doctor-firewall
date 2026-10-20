import { useState } from 'react';
import type { ChangeEvent, SyntheticEvent } from 'react';

import { ApiError, api, errorCode } from '../api/client';
import { TIERS } from '../api/types';
import type { Asset, Tier } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { Alert, Ltr } from '../components/common';
import { useApi, useSnapshotSelection } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';

type Message = { kind: 'error' | 'success'; text: string } | null;

function errorLines(body: unknown): string {
  if (typeof body !== 'object' || body === null || !('errors' in body) || !Array.isArray(body.errors)) return '?';
  return body.errors
    .map((e: unknown) => (typeof e === 'object' && e !== null && 'line' in e ? String(e.line) : '?'))
    .join(', ');
}
const EMPTY = { network: '', system: '', tier: 'GOLD' as Tier, system_type: '', user_type: '', ports: '' };
const MAX_FILE_BYTES = 1_000_000;

/** The asset table: the doctrine ground truth (manual, CSV, or bootstrap + confirm). */
export function AssetsPage() {
  const { t, tError } = useI18n();
  const { can } = useAuth();
  const writable = can('assets:write');
  const assets = useApi<Asset[]>('/api/assets');
  const { snapshotId } = useSnapshotSelection();
  const [form, setForm] = useState(EMPTY);
  const [message, setMessage] = useState<Message>(null);
  const pending = (assets.data ?? []).filter((a) => !a.confirmed);

  async function run(action: () => Promise<string>) {
    try {
      setMessage({ kind: 'success', text: await action() });
      assets.reload();
    } catch (err: unknown) {
      setMessage({ kind: 'error', text: tError(errorCode(err)) });
    }
  }

  async function add(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    await run(async () => {
      await api<Asset>('/api/assets', 'POST', {
        network: form.network.trim(),
        system: form.system.trim(),
        tier: form.tier,
        system_type: form.system_type.trim(),
        ports: form.ports.trim(),
        ...(form.user_type.trim() === '' ? {} : { user_type: form.user_type.trim() }),
      });
      setForm(EMPTY);
      return t('users.saved');
    });
  }

  async function importFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (file === undefined) return;
    if (file.size > MAX_FILE_BYTES) {
      setMessage({ kind: 'error', text: tError('request_too_large') });
      return;
    }
    const text = await file.text();
    try {
      const result = await api<{ created: number; updated: number }>('/api/assets/import', 'POST', { csv: text });
      setMessage({ kind: 'success', text: t('assets.importDone', result) });
      assets.reload();
    } catch (err: unknown) {
      if (err instanceof ApiError && err.code === 'csv_invalid_rows') {
        setMessage({ kind: 'error', text: t('assets.importErrors', { lines: errorLines(err.body) }) });
      } else {
        setMessage({ kind: 'error', text: tError(errorCode(err)) });
      }
    }
  }

  async function exportCsv() {
    const response = await fetch('/api/assets/export', { credentials: 'same-origin', cache: 'no-store' });
    if (!response.ok) return;
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement('a');
    link.href = url;
    link.download = 'assets.csv';
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="stack">
      <h1>{t('assets.title')}</h1>
      <p className="muted">{t('assets.help')}</p>
      {assets.error !== null && <Alert kind="error">{tError(assets.error)}</Alert>}
      {message !== null && <Alert kind={message.kind}>{message.text}</Alert>}

      <div className="row">
        <button type="button" className="secondary" onClick={() => void exportCsv()}>
          {t('assets.export')}
        </button>
        {writable && (
          <>
            <label className="button secondary">
              {t('assets.import')}
              <input type="file" accept=".csv,text/csv" className="visually-hidden" onChange={(e) => void importFile(e)} />
            </label>
            {snapshotId !== null && (
              <button
                type="button"
                className="secondary"
                onClick={() =>
                  void run(async () => {
                    const r = await api<{ created: number }>('/api/assets/bootstrap', 'POST', { snapshot_id: snapshotId });
                    return t('assets.bootstrapDone', { count: r.created });
                  })
                }
              >
                {t('assets.bootstrap')}
              </button>
            )}
            {pending.length > 0 && (
              <button
                type="button"
                onClick={() =>
                  void run(async () => {
                    await api('/api/assets/confirm', 'POST', { ids: pending.map((a) => a.id) });
                    return t('users.saved');
                  })
                }
              >
                {t('assets.confirmAll', { count: pending.length })}
              </button>
            )}
          </>
        )}
      </div>
      {writable && <p className="muted small">{t('assets.csvHelp')}</p>}

      <section className="card">
        <table>
          <thead>
            <tr>
              <th>{t('assets.network')}</th>
              <th>{t('assets.system')}</th>
              <th>{t('assets.tier')}</th>
              <th>{t('assets.systemType')}</th>
              <th>{t('assets.userType')}</th>
              <th>{t('assets.ports')}</th>
              <th>{t('assets.source')}</th>
              {writable && <th>{t('common.actions')}</th>}
            </tr>
          </thead>
          <tbody>
            {(assets.data ?? []).map((a) => (
              <tr key={a.id} className={a.confirmed ? '' : 'inactive'}>
                <td>
                  <Ltr>{a.network}</Ltr>
                </td>
                <td>{a.system}</td>
                <td>
                  <span className={`tier tier-${a.tier.toLowerCase()}`}>{a.tier}</span>
                </td>
                <td>{a.system_type}</td>
                <td>{a.user_type ?? ''}</td>
                <td>
                  <Ltr>{a.ports}</Ltr>
                </td>
                <td>
                  {a.source}
                  {!a.confirmed && <div className="muted small">{t('assets.pending')}</div>}
                </td>
                {writable && (
                  <td className="actions">
                    {!a.confirmed && (
                      <button
                        type="button"
                        onClick={() =>
                          void run(async () => {
                            await api('/api/assets/confirm', 'POST', { ids: [a.id] });
                            return t('users.saved');
                          })
                        }
                      >
                        {t('assets.confirm')}
                      </button>
                    )}
                    <button
                      type="button"
                      className="danger"
                      onClick={() =>
                        void run(async () => {
                          await api(`/api/assets/${String(a.id)}`, 'DELETE');
                          return t('users.saved');
                        })
                      }
                    >
                      {t('common.delete')}
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {writable && (
        <section className="card">
          <h2>{t('assets.add')}</h2>
          <form className="grid" onSubmit={(e) => void add(e)} noValidate>
            <label>
              {t('assets.network')}
              <input dir="ltr" maxLength={96} value={form.network} onChange={(e) => { setForm({ ...form, network: e.target.value }); }} />
            </label>
            <label>
              {t('assets.system')}
              <input maxLength={128} value={form.system} onChange={(e) => { setForm({ ...form, system: e.target.value }); }} />
            </label>
            <label>
              {t('assets.tier')}
              <select value={form.tier} onChange={(e) => { setForm({ ...form, tier: e.target.value as Tier }); }}>
                {TIERS.map((tier) => (
                  <option key={tier} value={tier}>
                    {tier}
                  </option>
                ))}
              </select>
            </label>
            <label>
              {t('assets.systemType')}
              <input maxLength={32} value={form.system_type} onChange={(e) => { setForm({ ...form, system_type: e.target.value }); }} />
            </label>
            <label>
              {t('assets.userType')}
              <input maxLength={16} value={form.user_type} onChange={(e) => { setForm({ ...form, user_type: e.target.value }); }} />
            </label>
            <label>
              {t('assets.ports')}
              <input dir="ltr" maxLength={256} value={form.ports} onChange={(e) => { setForm({ ...form, ports: e.target.value }); }} />
            </label>
            <button type="submit" disabled={form.network.trim() === '' || form.system.trim() === ''}>
              {t('common.create')}
            </button>
          </form>
        </section>
      )}
    </div>
  );
}
