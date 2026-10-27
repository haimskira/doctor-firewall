import { useState } from 'react';
import { Link } from 'react-router-dom';

import type { RefItem, Severity, Snapshot } from '../api/types';
import { useI18n } from '../i18n/I18nProvider';
import { Ltr } from './common';
import { ObjectHover } from './ObjectHover';

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
    <ObjectHover snapshotId={snapshotId} objectId={item.id}>
      <Link
        className={`chip obj kind-${item.kind ?? 'other'}`}
        to={`/objects/${encodeURIComponent(item.id)}?snapshot=${String(snapshotId)}`}
      >
        {(item.kind === 'sgt' || item.kind === 'dynamic') && (
          <span className="chip-kind">{t(`chip.kind.${item.kind}`)}</span>
        )}
        <Ltr>{item.name}</Ltr>
      </Link>
    </ObjectHover>
  );
}

/**
 * A rule cell's references. With ``limit``, only the first values are shown, followed by a
 * "+N more" toggle (as in the FMC rule table); "Any" when the field is empty.
 */
export function RefList({
  items,
  snapshotId,
  limit,
}: {
  items: RefItem[] | undefined;
  snapshotId: number;
  limit?: number;
}) {
  const { t } = useI18n();
  const [expanded, setExpanded] = useState(false);
  if (items === undefined || items.length === 0) {
    return <span className="muted">{t('rules.any')}</span>;
  }
  const hidden = limit === undefined || expanded ? 0 : Math.max(0, items.length - limit);
  const shown = hidden > 0 ? items.slice(0, limit) : items;
  return (
    <span className="chips-inline">
      {shown.map((item, i) => (
        <RefChip key={`${item.id ?? item.literal ?? ''}-${String(i)}`} item={item} snapshotId={snapshotId} />
      ))}
      {hidden > 0 && (
        <button
          type="button"
          className="more"
          onClick={() => {
            setExpanded(true);
          }}
        >
          {t('rules.more', { count: hidden })}
        </button>
      )}
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
