import { useState } from 'react';
import type { SyntheticEvent } from 'react';

import { errorCode } from '../api/client';
import { useAuth } from '../auth/AuthProvider';
import { Alert } from '../components/common';
import { useI18n } from '../i18n/I18nProvider';

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
    <div className="center-page">
      <form className="card narrow" onSubmit={(e) => void onSubmit(e)} noValidate>
        <div className="row spread">
          <h1>{t('login.title')}</h1>
          <button
            type="button"
            className="link"
            onClick={() => {
              setLanguage(language === 'he' ? 'en' : 'he');
            }}
          >
            {t('login.language')}
          </button>
        </div>
        <p className="muted">{t('app.tagline')}</p>
        {error !== null && <Alert kind="error">{error}</Alert>}
        <label>
          {t('login.username')}
          <input
            name="username"
            dir="ltr"
            autoComplete="username"
            required
            maxLength={64}
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
        <button type="submit" disabled={busy || username === '' || password === ''}>
          {t('login.submit')}
        </button>
      </form>
    </div>
  );
}
