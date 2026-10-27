import { useCallback, useEffect, useState } from 'react';
import type { SyntheticEvent } from 'react';
import { SortedTable } from '../components/sort';

import { api, errorCode } from '../api/client';
import { ALL_ROLES, AUTH_PROVIDERS } from '../api/types';
import type { AuthProviderName, Role, User } from '../api/types';
import { Alert, DateTime, Ltr } from '../components/common';
import { useI18n } from '../i18n/I18nProvider';

type Message = { kind: 'error' | 'success'; text: string } | null;

function RolePicker({
  value,
  onChange,
  idPrefix,
}: {
  value: Role[];
  onChange: (roles: Role[]) => void;
  idPrefix: string;
}) {
  const { t } = useI18n();
  return (
    <fieldset className="roles">
      {ALL_ROLES.map((role) => (
        <label key={role} className="inline" htmlFor={`${idPrefix}-${role}`}>
          <input
            id={`${idPrefix}-${role}`}
            type="checkbox"
            checked={value.includes(role)}
            onChange={(e) => {
              onChange(
                e.target.checked ? [...value, role].sort() : value.filter((r) => r !== role),
              );
            }}
          />
          {t(`role.${role}`)}
        </label>
      ))}
    </fieldset>
  );
}

export function UsersPage() {
  const { t, tError } = useI18n();
  const [users, setUsers] = useState<User[]>([]);
  const [message, setMessage] = useState<Message>(null);
  const [form, setForm] = useState({ username: '', display_name: '', password: '' });
  const [roles, setRoles] = useState<Role[]>(['viewer']);
  const [provider, setProvider] = useState<AuthProviderName>('local');
  const local = provider === 'local';
  const [resetFor, setResetFor] = useState<User | null>(null);
  const [resetValue, setResetValue] = useState('');

  const fail = useCallback(
    (err: unknown) => {
      setMessage({ kind: 'error', text: tError(errorCode(err)) });
    },
    [tError],
  );

  const reload = useCallback(() => {
    api<User[]>('/api/users').then(setUsers).catch(fail);
  }, [fail]);

  useEffect(reload, [reload]);

  async function create(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      await api<User>('/api/users', 'POST', {
        username: form.username.trim(),
        display_name: form.display_name.trim(),
        roles,
        auth_provider: provider,
        ...(local ? { temporary_password: form.password } : {}),
      });
      setForm({ username: '', display_name: '', password: '' });
      setRoles(['viewer']);
      setProvider('local');
      setMessage({ kind: 'success', text: t('users.saved') });
      reload();
    } catch (err: unknown) {
      fail(err);
    }
  }

  async function update(user: User, patch: { roles?: Role[]; is_active?: boolean }) {
    try {
      await api<User>(`/api/users/${String(user.id)}`, 'PATCH', patch);
      setMessage({ kind: 'success', text: t('users.saved') });
      reload();
    } catch (err: unknown) {
      fail(err);
    }
  }

  async function resetPassword(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    if (resetFor === null) return;
    try {
      await api<User>(`/api/users/${String(resetFor.id)}/reset-password`, 'POST', {
        temporary_password: resetValue,
      });
      setResetFor(null);
      setResetValue('');
      setMessage({ kind: 'success', text: t('users.saved') });
      reload();
    } catch (err: unknown) {
      fail(err);
    }
  }

  return (
    <div className="stack">
      <h1>{t('users.title')}</h1>
      {message !== null && <Alert kind={message.kind}>{message.text}</Alert>}

      <section className="card">
        <table>
          <SortedTable
            rows={users}
            columns={{ username: (user) => user.username, display: (user) => user.display_name, provider: (user) => user.auth_provider, roles: (user) => user.roles.join(', '), active: (user) => user.is_active, login: (user) => user.last_login_at }}
            head={(th) => (
              <tr>
                {th('username', t('users.username'))}
                {th('display', t('users.displayName'))}
                {th('provider', t('users.provider'))}
                {th('roles', t('users.roles'))}
                {th('active', t('users.active'))}
                {th('login', t('users.lastLogin'), true)}
                <th>{t('common.actions')}</th>
              </tr>
            )}
          >
            {(user) => (
              <tr key={user.id} className={user.is_active ? '' : 'inactive'}>
                <td>
                  <Ltr>{user.username}</Ltr>
                  {user.must_change_password && (
                    <div className="muted small">{t('users.pendingChange')}</div>
                  )}
                </td>
                <td>{user.display_name}</td>
                <td>{t(`users.provider.${user.auth_provider}`)}</td>
                <td>
                  <RolePicker
                    idPrefix={`u${String(user.id)}`}
                    value={user.roles}
                    onChange={(next) => {
                      if (next.length > 0) void update(user, { roles: next });
                    }}
                  />
                </td>
                <td>{user.is_active ? t('common.yes') : t('common.no')}</td>
                <td>
                  <DateTime value={user.last_login_at} />
                </td>
                <td className="actions">
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => void update(user, { is_active: !user.is_active })}
                  >
                    {user.is_active ? t('users.deactivate') : t('users.activate')}
                  </button>
                  {user.auth_provider === 'local' && (
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => {
                        setResetFor(user);
                        setResetValue('');
                      }}
                    >
                      {t('users.resetPassword')}
                    </button>
                  )}
                </td>
              </tr>
            )}
          </SortedTable>
        </table>
      </section>

      {resetFor !== null && (
        <section className="card">
          <h2>
            {t('users.resetPassword')}: <Ltr>{resetFor.username}</Ltr>
          </h2>
          <form className="row" onSubmit={(e) => void resetPassword(e)} noValidate>
            <label>
              {t('users.tempPassword')}
              <input
                type="password"
                dir="ltr"
                autoComplete="new-password"
                maxLength={128}
                value={resetValue}
                onChange={(e) => {
                  setResetValue(e.target.value);
                }}
              />
            </label>
            <button type="submit" disabled={resetValue === ''}>
              {t('common.save')}
            </button>
            <button
              type="button"
              className="secondary"
              onClick={() => {
                setResetFor(null);
              }}
            >
              {t('common.cancel')}
            </button>
          </form>
        </section>
      )}

      <section className="card">
        <h2>{t('users.create')}</h2>
        <form className="grid" onSubmit={(e) => void create(e)} noValidate>
          <label>
            {t('users.username')}
            <input
              dir="ltr"
              required
              maxLength={64}
              pattern="[A-Za-z0-9._@\-]+"
              value={form.username}
              onChange={(e) => {
                setForm({ ...form, username: e.target.value });
              }}
            />
          </label>
          <label>
            {t('users.displayName')}
            <input
              maxLength={128}
              value={form.display_name}
              onChange={(e) => {
                setForm({ ...form, display_name: e.target.value });
              }}
            />
          </label>
          <label>
            {t('users.provider')}
            <select
              value={provider}
              onChange={(e) => {
                const next = AUTH_PROVIDERS.find((p) => p === e.target.value);
                if (next !== undefined) setProvider(next);
              }}
            >
              {AUTH_PROVIDERS.map((p) => (
                <option key={p} value={p}>
                  {t(`users.provider.${p}`)}
                </option>
              ))}
            </select>
          </label>
          {local && (
            <label>
              {t('users.tempPassword')}
              <input
                type="password"
                dir="ltr"
                autoComplete="new-password"
                maxLength={128}
                value={form.password}
                onChange={(e) => {
                  setForm({ ...form, password: e.target.value });
                }}
              />
            </label>
          )}
          <RolePicker idPrefix="new" value={roles} onChange={setRoles} />
          <button
            type="submit"
            disabled={form.username === '' || (local && form.password === '') || roles.length === 0}
          >
            {t('common.create')}
          </button>
        </form>
        <p className="muted small">{local ? t('password.rules') : t('users.directoryHelp')}</p>
      </section>
    </div>
  );
}
