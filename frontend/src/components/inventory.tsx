import { Link } from 'react-router-dom';

import type { RefItem, Severity, Snapshot } from '../api/types';
import { useI18n } from '../i18n/I18nProvider';
import { Ltr } from './common';

/** An object reference (link to its explorer page) or an inline literal (flagged). */
export function RefChip({ item, snapshotId }: { item: RefItem; snapshotId: number }) {
  const { t } = useI18n();
  if (item.literal !== null) {
    return (
      <span className="chip literal" title={t('rules.literal')}>
        <Ltr>{item.literal}</Ltr>
      </span>
    );
  }
  if (item.id === null) return null;
  return (
    <Link
      className={`chip obj kind-${item.kind ?? 'other'}`}
      to={`/objects/${encodeURIComponent(item.id)}?snapshot=${String(snapshotId)}`}
    >
      <Ltr>{item.name}</Ltr>
    </Link>
  );
}

export function RefList({ items, snapshotId }: { items: RefItem[] | undefined; snapshotId: number }) {
  const { t } = useI18n();
  if (items === undefined || items.length === 0) {
    return <span className="muted">{t('rules.any')}</span>;
  }
  return (
    <span className="chips-inline">
      {items.map((item, i) => (
        <RefChip key={`${item.id ?? item.literal ?? ''}-${String(i)}`} item={item} snapshotId={snapshotId} />
      ))}
    </span>
  );
}

export function SnapshotPicker({
  snapshots,
  value,
  onChange,
}: {
  snapshots: Snapshot[];
  value: number | null;
  onChange: (id: number) => void;
}) {
  const { t, language } = useI18n();
  const fmt = new Intl.DateTimeFormat(language === 'he' ? 'he-IL' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'short',
  });
  return (
    <label className="inline-field">
      {t('snap.pick')}
      <select
        value={value ?? ''}
        onChange={(e) => {
          onChange(Number(e.target.value));
        }}
      >
        {snapshots.map((s) => (
          <option key={s.id} value={s.id}>
            #{s.id} · {s.connection_name} · {fmt.format(new Date(s.created_at))}
          </option>
        ))}
      </select>
    </label>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const { t } = useI18n();
  return <span className={`badge sev-${severity}`}>{t(`findings.sev.${severity}`)}</span>;
}
