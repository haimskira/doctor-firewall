import { useState } from 'react';
import type { SyntheticEvent } from 'react';

import { errorCode } from '../api/client';
import { useAuth } from '../auth/AuthProvider';
import { Alert } from '../components/common';
import { useI18n } from '../i18n/I18nProvider';

/** The product mark: a shield with a pulse line (our own, not a vendor logo). */
function BrandMark() {
  return (
    <svg className="login-mark" viewBox="0 0 48 48" aria-hidden="true" focusable="false">
      <path d="M24 3 6 9.5v13.2C6 34.3 13.7 42 24 45c10.3-3 18-10.7 18-22.3V9.5L24 3z" fill="#1d2b4f" />
      <path d="M11 25h7l3-7 5 14 4-10 2 3h5" fill="none" stroke="#6abf4b" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Sign-in, laid out like the firewall manager's own: a city at night, one white card. */
export function LoginPage() {
  const { t, tError, language, setLanguage } = useI18n();
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username.trim(), password);
    } catch (err: unknown) {
      setError(tError(errorCode(err)));
      setPassword('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <main className="login-card">
        <button
          type="button"
          className="link login-language"
          onClick={() => {
            setLanguage(language === 'he' ? 'en' : 'he');
          }}
        >
          {t('login.language')}
        </button>
        <div className="login-brand" dir="ltr">
          <BrandMark />
          <span className="login-brand-name">DOCTOR</span>
          <span className="login-brand-accent">FIREWALL</span>
        </div>
        <h1 className="login-title">
          <span>{t('login.heading1')}</span>
          <span>{t('login.heading2')}</span>
        </h1>
        <form className="login-form" onSubmit={(e) => void onSubmit(e)} noValidate aria-label={t('login.title')}>
          {error !== null && <Alert kind="error">{error}</Alert>}
          <label>
            {t('login.username')}
            <input
              name="username"
              dir="ltr"
              autoComplete="username"
              required
              maxLength={64}
              autoFocus
              value={username}
              onChange={(e) => {
                setUsername(e.target.value);
              }}
            />
          </label>
          <label>
            {t('login.password')}
            <input
              name="password"
              type="password"
              dir="ltr"
              autoComplete="current-password"
              required
              maxLength={128}
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
              }}
            />
          </label>
          <button type="submit" className="login-submit" disabled={busy || username === '' || password === ''}>
            {t('login.submit')}
          </button>
        </form>
      </main>
    </div>
  );
}
