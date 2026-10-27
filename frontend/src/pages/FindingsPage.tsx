import { useState } from 'react';

import type { FindingsPage as Page, Severity } from '../api/types';
import { Alert } from '../components/common';
import { FindingDetails, useFindingHeadline } from '../components/findings';
import { SeverityBadge, SnapshotPicker } from '../components/inventory';
import { useApi, useQueryParam, useSnapshotSelection } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';
import type { MessageKey } from '../i18n/messages';

const KINDS = [
  'ace_cluster_limit', 'shadowed_rule', 'group_cycle', 'identical_rules', 'dead_rule',
  'overlap_conflict', 'deep_nesting', 'ace_heavy_rule', 'duplicate_object', 'duplicate_membership',
  'inline_literal', 'unused_object',
] as const;
const SEVERITIES: Severity[] = ['high', 'medium', 'low', 'info'];

export function FindingsPage() {
  const { t, tError } = useI18n();
  const { snapshots, snapshotId, setSnapshotId, error: snapError } = useSnapshotSelection();
  const [kind, setKind] = useQueryParam('kind');
  const [severity, setSeverity] = useQueryParam('severity');
  const [open, setOpen] = useState<number | null>(null);
  const headline = useFindingHeadline();
  const params = new URLSearchParams({ limit: '500' });
  if (kind !== null) params.set('kind', kind);
  if (severity !== null) params.set('severity', severity);
  const page = useApi<Page>(snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}/findings?${params.toString()}`);
  const error = snapError ?? page.error;

  const counts = new Map(
    Object.entries(page.data?.summary ?? {}).map(([k, bySeverity]) => [
      k,
      Object.values(bySeverity).reduce<number>((sum, n) => sum + n, 0),
    ]),
  );
  const countFor = (k: string) => counts.get(k) ?? 0;

  return (
    <div className="stack">
      <div className="row spread">
        <h1>{t('findings.title')}</h1>
        <SnapshotPicker snapshots={snapshots} value={snapshotId} onChange={setSnapshotId} />
      </div>
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      {snapshotId === null && snapError === null && <Alert kind="info">{t('snap.none')}</Alert>}
      {page.data !== null && (
        <>
          <div className="row" role="group" aria-label={t('objects.kind')}>
            <button type="button" className={kind === null ? '' : 'secondary'} onClick={() => { setKind(null); }}>
              {t('findings.all')}
            </button>
            {KINDS.map((k) => (
              <button
                key={k}
                type="button"
                className={kind === k ? '' : 'secondary'}
                onClick={() => {
                  setKind(k);
                }}
              >
                {t(`findings.kind.${k}` as MessageKey)} ({countFor(k)})
              </button>
            ))}
          </div>
          <label className="inline-field">
            {t('findings.severity')}
            <select
              value={severity ?? ''}
              onChange={(e) => {
                setSeverity(e.target.value === '' ? null : e.target.value);
              }}
            >
              <option value="">{t('findings.all')}</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {t(`findings.sev.${s}`)}
                </option>
              ))}
            </select>
          </label>
          <section className="card">
            <p className="muted">{t('common.total', { count: page.data.total })}</p>
            <ul className="findings">
              {page.data.rows.map((f) => (
                <li key={f.id}>
                  <button
                    type="button"
                    className="link finding-title"
                    aria-expanded={open === f.id}
                    onClick={() => {
                      setOpen(open === f.id ? null : f.id);
                    }}
                  >
                    <SeverityBadge severity={f.severity} /> <bdi>{headline(f)}</bdi>
                  </button>
                  {open === f.id && snapshotId !== null && <FindingDetails finding={f} snapshotId={snapshotId} />}
                </li>
              ))}
            </ul>
          </section>
        </>
      )}
    </div>
  );
}
