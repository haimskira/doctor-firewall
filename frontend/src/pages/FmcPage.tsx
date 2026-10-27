import { useCallback, useEffect, useState } from 'react';
import type { SyntheticEvent } from 'react';
import { SortedTable } from '../components/sort';

import { api, errorCode } from '../api/client';
import type { FmcConnection, FmcTestResult } from '../api/types';
import { Alert, DateTime, Ltr } from '../components/common';
import { useI18n } from '../i18n/I18nProvider';

interface FormState {
  name: string;
  host: string;
  port: string;
  username: string;
  password: string;
  sync: string; // minutes; empty = manual only
}

const EMPTY: FormState = { name: '', host: '', port: '443', username: '', password: '', sync: '' };

type Message = { kind: 'error' | 'success'; text: string } | null;

export function FmcPage() {
  const { t, tError } = useI18n();
  const [connections, setConnections] = useState<FmcConnection[]>([]);
  const [form, setForm] = useState<FormState>(EMPTY);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [message, setMessage] = useState<Message>(null);
  const [testing, setTesting] = useState<number | null>(null);

  const fail = useCallback(
    (err: unknown) => {
      setMessage({ kind: 'error', text: tError(errorCode(err)) });
    },
    [tError],
  );

  const reload = useCallback(() => {
    api<FmcConnection[]>('/api/fmc/connections').then(setConnections).catch(fail);
  }, [fail]);

  useEffect(reload, [reload]);

  function startEdit(conn: FmcConnection) {
    setEditingId(conn.id);
    setForm({
      name: conn.name,
      host: conn.host,
      port: String(conn.port),
      username: conn.username,
      password: '',
      sync: conn.sync_interval_minutes === null ? '' : String(conn.sync_interval_minutes),
    });
  }

  async function save(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const sync = form.sync.trim() === '' ? null : Number(form.sync);
    const base = {
      name: form.name.trim(),
      host: form.host.trim(),
      port: Number(form.port),
      username: form.username.trim(),
    };
    try {
      if (editingId === null) {
        await api<FmcConnection>('/api/fmc/connections', 'POST', {
          ...base,
          password: form.password,
          sync_interval_minutes: sync,
        });
      } else {
        await api<FmcConnection>(
          `/api/fmc/connections/${String(editingId)}`,
          'PATCH',
          {
            ...base,
            ...(form.password === '' ? {} : { password: form.password }),
            ...(sync === null ? { disable_sync: true } : { sync_interval_minutes: sync }),
          },
        );
      }
      setForm(EMPTY);
      setEditingId(null);
      setMessage(null);
      reload();
    } catch (err: unknown) {
      fail(err);
    }
  }

  async function test(conn: FmcConnection) {
    setTesting(conn.id);
    setMessage(null);
    try {
      const result = await api<FmcTestResult>(
        `/api/fmc/connections/${String(conn.id)}/test`,
        'POST',
      );
      setMessage(
        result.ok
          ? {
              kind: 'success',
              text: t('fmc.testOk', {
                version: result.server_version ?? '?',
                domain: result.domain_uuid ?? '?',
              }),
            }
          : {
              kind: 'error',
              text: t('fmc.testFailed', { error: tError(result.error ?? 'unknown') }),
            },
      );
      reload();
    } catch (err: unknown) {
      fail(err);
    } finally {
      setTesting(null);
    }
  }

  async function remove(conn: FmcConnection) {
    if (!window.confirm(t('common.confirmDelete', { name: conn.name }))) return;
    try {
      await api<undefined>(`/api/fmc/connections/${String(conn.id)}`, 'DELETE');
      reload();
    } catch (err: unknown) {
      fail(err);
    }
  }

  const creating = editingId === null;
  const formValid =
    form.name !== '' &&
    form.host !== '' &&
    form.username !== '' &&
    /^\d{1,5}$/.test(form.port) &&
    (form.sync.trim() === '' || /^\d{2,5}$/.test(form.sync.trim())) &&
    (!creating || form.password !== '');

  return (
    <div className="stack">
      <h1>{t('fmc.title')}</h1>
      <p className="muted">{t('fmc.help')}</p>
      {message !== null && <Alert kind={message.kind}>{message.text}</Alert>}

      {connections.length > 0 && (
        <section className="card">
          <table>
            <SortedTable
              rows={connections}
              columns={{ name: (conn) => conn.name, host: (conn) => conn.host, user: (conn) => conn.username, version: (conn) => conn.server_version, domain: (conn) => conn.domain_uuid, tested: (conn) => conn.last_test_at, sync: (conn) => conn.sync_interval_minutes }}
              head={(th) => (
                <tr>
                  {th('name', t('fmc.name'))}
                  {th('host', t('fmc.host'))}
                  {th('user', t('fmc.username'))}
                  {th('version', t('fmc.version'))}
                  {th('domain', t('fmc.domain'))}
                  {th('tested', t('fmc.lastTest'), true)}
                  {th('sync', t('fmc.sync'), true)}
                  <th>t('common.actions')</th>
                </tr>
              )}
            >
              {(conn) => (
                <tr key={conn.id}>
                  <td>{conn.name}</td>
                  <td>
                    <Ltr>
                      {conn.host}:{conn.port}
                    </Ltr>
                  </td>
                  <td>
                    <Ltr>{conn.username}</Ltr>
                  </td>
                  <td>
                    <Ltr>{conn.server_version ?? '—'}</Ltr>
                  </td>
                  <td>
                    <Ltr>{conn.domain_uuid ?? '—'}</Ltr>
                  </td>
                  <td>
                    <DateTime value={conn.last_test_at} />{' '}
                    {conn.last_test_ok === true && <span className="ok">✔</span>}
                    {conn.last_test_ok === false && <span className="bad">✘</span>}
                  </td>
                  <td>{conn.sync_interval_minutes === null ? t('fmc.syncOff') : `${String(conn.sync_interval_minutes)}′`}</td>
                  <td className="actions">
                    <button
                      type="button"
                      disabled={testing !== null}
                      onClick={() => void test(conn)}
                    >
                      {testing === conn.id ? t('common.loading') : t('fmc.test')}
                    </button>
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => {
                        startEdit(conn);
                      }}
                    >
                      {t('common.edit')}
                    </button>
                    <button type="button" className="danger" onClick={() => void remove(conn)}>
                      {t('common.delete')}
                    </button>
                  </td>
                </tr>
              )}
            </SortedTable>
          </table>
        </section>
      )}

      <section className="card">
        <h2>{creating ? t('fmc.add') : t('common.edit')}</h2>
        <form className="grid" onSubmit={(e) => void save(e)} noValidate>
          <label>
            {t('fmc.name')}
            <input
              maxLength={64}
              value={form.name}
              onChange={(e) => {
                setForm({ ...form, name: e.target.value });
              }}
            />
          </label>
          <label>
            {t('fmc.host')}
            <input
              dir="ltr"
              maxLength={253}
              value={form.host}
              onChange={(e) => {
                setForm({ ...form, host: e.target.value });
              }}
            />
          </label>
          <label>
            {t('fmc.port')}
            <input
              dir="ltr"
              inputMode="numeric"
              maxLength={5}
              value={form.port}
              onChange={(e) => {
                setForm({ ...form, port: e.target.value });
              }}
            />
          </label>
          <label>
            {t('fmc.username')}
            <input
              dir="ltr"
              maxLength={64}
              autoComplete="off"
              value={form.username}
              onChange={(e) => {
                setForm({ ...form, username: e.target.value });
              }}
            />
          </label>
          <label>
            {t('fmc.password')}
            <input
              type="password"
              dir="ltr"
              maxLength={128}
              autoComplete="new-password"
              placeholder={creating ? '' : t('fmc.passwordKeep')}
              value={form.password}
              onChange={(e) => {
                setForm({ ...form, password: e.target.value });
              }}
            />
          </label>
          <label>
            {t('fmc.syncMinutes')}
            <input
              dir="ltr"
              inputMode="numeric"
              maxLength={5}
              placeholder={t('fmc.syncOff')}
              value={form.sync}
              onChange={(e) => {
                setForm({ ...form, sync: e.target.value });
              }}
            />
          </label>
          <div className="row">
            <button type="submit" disabled={!formValid}>
              {t('common.save')}
            </button>
            {!creating && (
              <button
                type="button"
                className="secondary"
                onClick={() => {
                  setEditingId(null);
                  setForm(EMPTY);
                }}
              >
                {t('common.cancel')}
              </button>
            )}
          </div>
        </form>
      </section>
    </div>
  );
}
