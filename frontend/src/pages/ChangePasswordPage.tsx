import { useState } from 'react';
import type { SyntheticEvent } from 'react';

import { api, errorCode } from '../api/client';
import type { Me } from '../api/types';
import { useAuth, useMe } from '../auth/AuthProvider';
import { Alert } from '../components/common';
import { useI18n } from '../i18n/I18nProvider';

export const MIN_PASSWORD_LENGTH = 12;

export function ChangePasswordPage() {
  const { t, tError } = useI18n();
  const { setMe } = useAuth();
  const me = useMe();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [message, setMessage] = useState<{ kind: 'error' | 'success'; text: string } | null>(null);

  async function onSubmit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    if (next.length < MIN_PASSWORD_LENGTH) {
      setMessage({ kind: 'error', text: t('password.tooShort') });
      return;
    }
    if (next !== confirm) {
      setMessage({ kind: 'error', text: t('password.mismatch') });
      return;
    }
    try {
      const updated = await api<Me>('/api/auth/change-password', 'POST', {
        current_password: current,
        new_password: next,
      });
      setCurrent('');
      setNext('');
      setConfirm('');
      setMessage({ kind: 'success', text: t('password.changed') });
      setMe(updated);
    } catch (err: unknown) {
      setMessage({ kind: 'error', text: tError(errorCode(err)) });
    }
  }

  return (
    <section className="card narrow">
      <h1>{t('password.title')}</h1>
      {me.must_change_password && <Alert kind="info">{t('password.forced')}</Alert>}
      {message !== null && <Alert kind={message.kind}>{message.text}</Alert>}
      <p className="muted">{t('password.rules')}</p>
      <form onSubmit={(e) => void onSubmit(e)} noValidate>
        <label>
          {t('password.current')}
          <input
            type="password"
            dir="ltr"
            autoComplete="current-password"
            value={current}
            onChange={(e) => {
              setCurrent(e.target.value);
            }}
          />
        </label>
        <label>
          {t('password.new')}
          <input
            type="password"
            dir="ltr"
            autoComplete="new-password"
            maxLength={128}
            value={next}
            onChange={(e) => {
              setNext(e.target.value);
            }}
          />
        </label>
        <label>
          {t('password.confirm')}
          <input
            type="password"
            dir="ltr"
            autoComplete="new-password"
            maxLength={128}
            value={confirm}
            onChange={(e) => {
              setConfirm(e.target.value);
            }}
          />
        </label>
        <button type="submit" disabled={current === '' || next === '' || confirm === ''}>
          {t('common.save')}
        </button>
      </form>
    </section>
  );
}
