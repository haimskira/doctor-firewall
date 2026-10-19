import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

import type { Language } from '../api/types';
import { en, he } from './messages';
import type { MessageKey } from './messages';

const CATALOGS: Record<Language, Record<MessageKey, string>> = { en, he };

export type Translate = (key: MessageKey, vars?: Record<string, string | number>) => string;

interface I18nValue {
  language: Language;
  dir: 'rtl' | 'ltr';
  setLanguage: (language: Language) => void;
  t: Translate;
  /** Translate a backend error code, falling back to a generic message. */
  tError: (code: string) => string;
}

const I18nContext = createContext<I18nValue | null>(null);

export function interpolate(template: string, vars: Record<string, string | number> = {}): string {
  const values = new Map(Object.entries(vars));
  return template.replace(/\{(\w+)\}/g, (match, name: string) => {
    const value = values.get(name);
    return value === undefined ? match : String(value);
  });
}

function isMessageKey(key: string): key is MessageKey {
  return Object.prototype.hasOwnProperty.call(en, key);
}

export function I18nProvider({
  children,
  initial = 'he',
}: {
  children: ReactNode;
  initial?: Language;
}) {
  const [language, setLanguage] = useState<Language>(initial);
  const dir = language === 'he' ? 'rtl' : 'ltr';

  useEffect(() => {
    document.documentElement.lang = language;
    document.documentElement.dir = dir;
  }, [language, dir]);

  const t = useCallback<Translate>(
    // Both indexes are closed TypeScript unions (Language, MessageKey), not user input.
    // eslint-disable-next-line security/detect-object-injection
    (key, vars) => interpolate(CATALOGS[language][key], vars),
    [language],
  );

  const tError = useCallback(
    (code: string) => {
      const key = `error.${code}`;
      return isMessageKey(key) ? t(key) : t('error.unknown', { code });
    },
    [t],
  );

  const value = useMemo(
    () => ({ language, dir, setLanguage, t, tError }) satisfies I18nValue,
    [language, dir, t, tError],
  );
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nValue {
  const ctx = useContext(I18nContext);
  if (ctx === null) {
    throw new Error('useI18n must be used inside <I18nProvider>');
  }
  return ctx;
}
