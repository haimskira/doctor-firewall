import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { api, errorCode } from '../api/client';
import type { FwObject, ObjectsPage as Page } from '../api/types';
import { Alert, Ltr } from '../components/common';
import { SnapshotPicker } from '../components/inventory';
import { SortTh, useServerSort } from '../components/sort';
import { useQueryParam, useSnapshotSelection } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';

const KINDS = [
  'host', 'network', 'range', 'fqdn', 'network_group', 'port', 'port_group', 'icmp', 'zone',
  'sgt', 'dynamic', 'application', 'url', 'url_group', 'geo', 'other',
] as const;
const PAGE = 100;
const SORTS = ['name', 'kind', 'value', 'rule_refs', 'member_of'] as const;

export function ObjectsPage() {
  const { t, tError } = useI18n();
  const { snapshots, snapshotId, setSnapshotId, error: snapError } = useSnapshotSelection();
  const [kind, setKind] = useQueryParam('kind');
  const [q, setQ] = useQueryParam('q');
  const [search, setSearch] = useState(q ?? '');
  const [rows, setRows] = useState<FwObject[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const sort = useServerSort(SORTS);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setQ(search.trim() === '' ? null : search.trim());
    }, 300);
    return () => {
      window.clearTimeout(timer);
    };
  }, [search, setQ]);

  function url(offset: number): string | null {
    if (snapshotId === null) return null;
    const params = new URLSearchParams({ offset: String(offset), limit: String(PAGE) });
    if (kind !== null) params.set('kind', kind);
    if (q !== null) params.set('q', q);
    for (const [k, v] of Object.entries(sort.query)) params.set(k, v);
    return `/api/snapshots/${String(snapshotId)}/objects?${params.toString()}`;
  }

  const first = url(0);
  useEffect(() => {
    if (first === null) return;
    let cancelled = false;
    api<Page>(first)
      .then((page) => {
        if (cancelled) return;
        setRows(page.rows);
        setTotal(page.total);
        setError(null);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorCode(err));
      });
    return () => {
      cancelled = true;
    };
  }, [first]);

  async function more() {
    const next = url(rows.length);
    if (next === null) return;
    try {
      const page = await api<Page>(next);
      setRows((prev) => [...prev, ...page.rows]);
    } catch (err: unknown) {
      setError(errorCode(err));
    }
  }

  return (
    <div className="stack">
      <div className="row spread">
        <h1>{t('objects.title')}</h1>
        <SnapshotPicker snapshots={snapshots} value={snapshotId} onChange={setSnapshotId} />
      </div>
      {(snapError ?? error) !== null && <Alert kind="error">{tError(snapError ?? error ?? '')}</Alert>}
      {snapshotId === null && snapError === null && <Alert kind="info">{t('snap.none')}</Alert>}
      {snapshotId !== null && (
        <>
          <div className="row">
            <label className="inline-field">
              {t('objects.kind')}
              <select
                value={kind ?? ''}
                onChange={(e) => {
                  setKind(e.target.value === '' ? null : e.target.value);
                }}
              >
                <option value="">{t('objects.all')}</option>
                {KINDS.map((k) => (
                  <option key={k} value={k}>
                    {k}
                  </option>
                ))}
              </select>
            </label>
            <label className="inline-field grow">
              {t('common.search')}
              <input
                type="search"
                dir="auto"
                maxLength={128}
                placeholder={t('objects.search')}
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                }}
              />
            </label>
            <span className="muted">{t('common.total', { count: total })}</span>
          </div>
          <section className="card">
            <table>
              <thead>
                <tr>
                  <SortTh label={t('objects.col.name')} sortKey="name" state={sort.state} onSort={sort.onSort} />
                  <SortTh label={t('objects.col.kind')} sortKey="kind" state={sort.state} onSort={sort.onSort} />
                  <SortTh label={t('objects.col.value')} sortKey="value" state={sort.state} onSort={sort.onSort} />
                  <SortTh label={t('objects.col.rules')} sortKey="rule_refs" state={sort.state} onSort={sort.onSort} numeric />
                  <SortTh label={t('objects.col.groups')} sortKey="member_of" state={sort.state} onSort={sort.onSort} numeric />
                </tr>
              </thead>
              <tbody>
                {rows.map((o) => (
                  <tr key={o.id}>
                    <td>
                      <Link to={`/objects/${encodeURIComponent(o.id)}?snapshot=${String(snapshotId)}`}>
                        <Ltr>{o.name}</Ltr>
                      </Link>
                      {o.stub && <div className="muted small">{t('objects.stub')}</div>}
                    </td>
                    <td>{o.kind}</td>
                    <td>
                      <Ltr>{o.value ?? ''}</Ltr>
                    </td>
                    <td className={o.rule_refs === 0 ? 'muted' : ''}>{o.rule_refs}</td>
                    <td className={o.member_of === 0 ? 'muted' : ''}>{o.member_of}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {rows.length < total && (
              <button type="button" className="secondary" onClick={() => void more()}>
                {t('common.loadMore')}
              </button>
            )}
          </section>
        </>
      )}
    </div>
  );
}
