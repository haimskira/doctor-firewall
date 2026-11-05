import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { api, errorCode } from '../api/client';
import type { FwObject, ObjectKinds, ObjectsPage as Page } from '../api/types';
import { Alert, Ltr } from '../components/common';
import { SnapshotPicker } from '../components/inventory';
import { PolicyPicker, ScopeNote, usePolicyScope } from '../components/policyScope';
import { SortTh, useServerSort } from '../components/sort';
import { useApi, useQueryParam, useSetQueryParams, useSnapshotSelection } from '../hooks';
import { isMessageKey, useI18n } from '../i18n/I18nProvider';

/** Tabs: object kinds grouped the way they are managed (addresses, services, identity...). */
const CATEGORIES = [
  { id: 'network', kinds: ['host', 'network', 'range', 'fqdn', 'network_group'] },
  { id: 'service', kinds: ['port', 'port_group', 'icmp'] },
  { id: 'zone', kinds: ['zone'] },
  { id: 'identity', kinds: ['sgt', 'dynamic'] },
  { id: 'application', kinds: ['application', 'url', 'url_group', 'geo'] },
] as const;
type CategoryId = (typeof CATEGORIES)[number]['id'] | 'other';
const KNOWN: ReadonlySet<string> = new Set(CATEGORIES.flatMap((c) => c.kinds));
const PAGE = 100;
const SORTS = ['name', 'kind', 'value', 'rule_refs', 'member_of'] as const;
const USAGES = ['used', 'unused'] as const;

function categoryOf(kind: string): CategoryId {
  return CATEGORIES.find((c) => (c.kinds as readonly string[]).includes(kind))?.id ?? 'other';
}

function kindsOf(category: CategoryId, present: string[]): string[] {
  if (category === 'other') return present.filter((k) => !KNOWN.has(k));
  return [...(CATEGORIES.find((c) => c.id === category)?.kinds ?? [])];
}

export function ObjectsPage() {
  const { t, tError } = useI18n();
  const { snapshots, snapshotId, setSnapshotId, error: snapError } = useSnapshotSelection();
  const [tabParam] = useQueryParam('tab');
  const [kind] = useQueryParam('kind');
  const [usageParam] = useQueryParam('usage');
  const [q, setQ] = useQueryParam('q');
  const setParams = useSetQueryParams();
  const [search, setSearch] = useState(q ?? '');
  const [rows, setRows] = useState<FwObject[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const sort = useServerSort(SORTS);
  const scope = usePolicyScope(snapshotId);

  const tab: CategoryId | null =
    tabParam === 'other' || CATEGORIES.some((c) => c.id === tabParam) ? (tabParam as CategoryId) : null;
  const usage = USAGES.find((u) => u === usageParam) ?? null;

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setQ(search.trim() === '' ? null : search.trim());
    }, 300);
    return () => {
      window.clearTimeout(timer);
    };
  }, [search, setQ]);

  const countParams = new URLSearchParams();
  if (q !== null) countParams.set('q', q);
  if (scope.policy !== null) countParams.set('policy', scope.policy);
  const counts = useApi<ObjectKinds>(
    snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}/object-kinds?${countParams.toString()}`,
  );
  const byKind = new Map((counts.data?.kinds ?? []).map((k) => [k.kind, k]));
  const present = [...byKind.keys()];
  const sumOf = (kinds: string[], field: 'total' | 'unused') =>
    kinds.reduce((n, k) => {
      const row = byKind.get(k);
      return n + (row === undefined ? 0 : field === 'total' ? row.total : row.unused);
    }, 0);
  const allTotal = sumOf(present, 'total');
  const tabs = [...CATEGORIES.map((c) => c.id), 'other' as const]
    .map((id) => ({ id, kinds: kindsOf(id, present).filter((k) => byKind.has(k)) }))
    .filter((c) => c.kinds.length > 0 || c.id === tab);
  const tabKinds = tab === null ? present : kindsOf(tab, present);
  const visibleKinds = tabKinds.filter((k) => byKind.has(k));
  // A tab whose kinds are all absent still filters (to nothing) instead of showing everything.
  const queryKinds = kind !== null ? [kind] : tab === null ? [] : tabKinds.length > 0 ? tabKinds : ['none'];

  function url(offset: number): string | null {
    if (snapshotId === null) return null;
    const params = new URLSearchParams({ offset: String(offset), limit: String(PAGE) });
    for (const k of queryKinds) params.append('kind', k);
    if (usage !== null) params.set('usage', usage);
    if (q !== null) params.set('q', q);
    if (scope.policy !== null) params.set('policy', scope.policy);
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

  function tabLabel(id: CategoryId): string {
    const key = `objects.tab.${id}`;
    return isMessageKey(key) ? t(key) : id;
  }

  function kindLabel(k: string): string {
    const key = `objects.kind.${k}`;
    return isMessageKey(key) ? t(key) : k;
  }

  const scopeKinds = kind !== null ? [kind] : visibleKinds;
  const unusedHere = sumOf(scopeKinds, 'unused');
  const totalHere = sumOf(scopeKinds, 'total');

  return (
    <div className="stack">
      <div className="row spread">
        <h1>{t('objects.title')}</h1>
        <div className="row page-filters">
          <SnapshotPicker snapshots={snapshots} value={snapshotId} onChange={setSnapshotId} />
          <PolicyPicker scope={scope} />
        </div>
      </div>
      <ScopeNote scope={scope} />
      {(snapError ?? error ?? counts.error) !== null && (
        <Alert kind="error">{tError(snapError ?? error ?? counts.error ?? '')}</Alert>
      )}
      {snapshotId === null && snapError === null && <Alert kind="info">{t('snap.none')}</Alert>}
      {snapshotId !== null && (
        <>
          <nav className="obj-tabs" role="tablist" aria-label={t('objects.categories')}>
            {[{ id: null, kinds: present }, ...tabs].map((c) => {
              const selected = c.id === tab;
              const count = c.id === null ? allTotal : sumOf(c.kinds, 'total');
              return (
                <button
                  key={c.id ?? 'all'}
                  type="button"
                  role="tab"
                  aria-selected={selected}
                  className={`obj-tab${selected ? ' active' : ''}${c.id === null ? '' : ` cat-${c.id}`}`}
                  onClick={() => {
                    setParams({ tab: c.id, kind: null });
                  }}
                >
                  <span>{c.id === null ? t('objects.all') : tabLabel(c.id)}</span>
                  <span className="obj-tab-count">{count.toLocaleString()}</span>
                </button>
              );
            })}
          </nav>

          <section className="card obj-panel" role="tabpanel">
            <div className="obj-toolbar">
              {visibleKinds.length > 1 && (
                <div className="obj-kinds" role="group" aria-label={t('objects.kind')}>
                  <button
                    type="button"
                    className={`obj-kind${kind === null ? ' active' : ''}`}
                    aria-pressed={kind === null}
                    onClick={() => {
                      setParams({ kind: null });
                    }}
                  >
                    {t('objects.allKinds')}
                  </button>
                  {visibleKinds.map((k) => (
                    <button
                      key={k}
                      type="button"
                      className={`obj-kind${kind === k ? ' active' : ''}`}
                      aria-pressed={kind === k}
                      onClick={() => {
                        setParams({ kind: kind === k ? null : k });
                      }}
                    >
                      {kindLabel(k)} <span className="muted">{(byKind.get(k)?.total ?? 0).toLocaleString()}</span>
                    </button>
                  ))}
                </div>
              )}
              <div className="row obj-filters">
                <div className="segmented" role="group" aria-label={t('objects.usage')}>
                  {([null, ...USAGES] as const).map((u) => (
                    <button
                      key={u ?? 'all'}
                      type="button"
                      className={usage === u ? 'active' : ''}
                      aria-pressed={usage === u}
                      onClick={() => {
                        setParams({ usage: u });
                      }}
                    >
                      {u === null
                        ? t('objects.usage.all')
                        : u === 'used'
                          ? t('objects.usage.used', { count: totalHere - unusedHere })
                          : t('objects.usage.unused', { count: unusedHere })}
                    </button>
                  ))}
                </div>
                <label className="inline-field grow">
                  <span className="visually-hidden">{t('common.search')}</span>
                  <input
                    type="search"
                    dir="auto"
                    maxLength={128}
                    aria-label={t('common.search')}
                    placeholder={t('objects.search')}
                    value={search}
                    onChange={(e) => {
                      setSearch(e.target.value);
                    }}
                  />
                </label>
                <span className="muted">{t('common.total', { count: total })}</span>
              </div>
            </div>
            {rows.length === 0 ? (
              <p className="muted obj-empty">{t('objects.empty')}</p>
            ) : (
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
                  {rows.map((o) => {
                    const unused = o.rule_refs === 0 && o.member_of === 0;
                    return (
                      <tr key={o.id} className={unused ? 'obj-unused' : ''}>
                        <td>
                          <Link to={`/objects/${encodeURIComponent(o.id)}?snapshot=${String(snapshotId)}`}>
                            <Ltr>{o.name}</Ltr>
                          </Link>
                          {o.stub && <div className="muted small">{t('objects.stub')}</div>}
                        </td>
                        <td>
                          <span className={`obj-kind-badge cat-${categoryOf(o.kind)}`}>{kindLabel(o.kind)}</span>
                        </td>
                        <td className="obj-value">
                          <Ltr>{o.value ?? ''}</Ltr>
                        </td>
                        <td className={o.rule_refs === 0 ? 'muted' : ''}>{o.rule_refs}</td>
                        <td className={o.member_of === 0 ? 'muted' : ''}>
                          {o.member_of}
                          {unused && <span className="badge obj-unused-badge">{t('objects.unusedBadge')}</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
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
