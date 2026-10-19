import type { ReactNode } from 'react';

import { useI18n } from '../i18n/I18nProvider';

/**
 * Left-to-right island inside RTL text: IPs, ACLs, object names, hashes, versions.
 * <bdi> isolates the bidi run so punctuation does not jump around in Hebrew.
 */
export function Ltr({ children }: { children: ReactNode }) {
  return (
    <bdi dir="ltr" className="ltr">
      {children}
    </bdi>
  );
}

export function Alert({ kind, children }: { kind: 'error' | 'success' | 'info'; children: ReactNode }) {
  return (
    <div role={kind === 'error' ? 'alert' : 'status'} className={`alert alert-${kind}`}>
      {children}
    </div>
  );
}

export function DateTime({ value }: { value: string | null }) {
  const { t, language } = useI18n();
  if (value === null) return <span className="muted">{t('common.never')}</span>;
  const formatted = new Intl.DateTimeFormat(language === 'he' ? 'he-IL' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'medium',
  }).format(new Date(value));
  return (
    <time dateTime={value}>
      <Ltr>{formatted}</Ltr>
    </time>
  );
}
