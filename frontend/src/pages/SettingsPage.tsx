import { useState } from 'react';
import { Link } from 'react-router-dom';

import { api, errorCode } from '../api/client';
import type { Language, Me, Theme } from '../api/types';
import { useAuth, useMe } from '../auth/AuthProvider';
import { Alert } from '../components/common';
import { useI18n } from '../i18n/I18nProvider';

export function SettingsPage() {
  const { t, tError } = useI18n();
  const { setMe } = useAuth();
  const me = useMe();
  const [message, setMessage] = useState<{ kind: 'error' | 'success'; text: string } | null>(null);

  async function choose(change: { language?: Language; theme?: Theme }) {
    try {
      const updated = await api<Me>('/api/me/preferences', 'PATCH', change);
      setMe(updated);
      setMessage({ kind: 'success', text: t('settings.saved') });
    } catch (err: unknown) {
      setMessage({ kind: 'error', text: tError(errorCode(err)) });
    }
  }

  return (
    <div className="stack">
      <h1>{t('settings.title')}</h1>
      {message !== null && <Alert kind={message.kind}>{message.text}</Alert>}
      <section className="card">
        <h2>{t('settings.language')}</h2>
        <div className="row" role="radiogroup" aria-label={t('settings.language')}>
          {(['he', 'en'] as const).map((lang) => (
            <label key={lang} className="inline">
              <input
                type="radio"
                name="language"
                checked={me.language === lang}
                onChange={() => void choose({ language: lang })}
              />
              {lang === 'he' ? 'עברית' : 'English'}
            </label>
          ))}
        </div>
      </section>
      <section className="card">
        <h2>{t('settings.theme')}</h2>
        <div className="row" role="radiogroup" aria-label={t('settings.theme')}>
          {(['system', 'light', 'dark'] as const).map((theme) => (
            <label key={theme} className="inline">
              <input
                type="radio"
                name="theme"
                checked={me.theme === theme}
                onChange={() => void choose({ theme })}
              />
              {t(`settings.theme.${theme}`)}
            </label>
          ))}
        </div>
      </section>
      <section className="card">
        <Link to="/password">{t('password.title')}</Link>
      </section>
    </div>
  );
}
