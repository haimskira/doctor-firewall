import { useVirtualizer } from '@tanstack/react-virtual';
import { useEffect, useMemo, useRef, useState } from 'react';

import { api, errorCode } from '../api/client';
import type { Cluster, RuleRow, RulesPage } from '../api/types';
import { Alert, Ltr } from '../components/common';
import { RefList, SnapshotPicker } from '../components/inventory';
import { useApi, useQueryParam, useSnapshotSelection } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';

const PAGE = 200;
const ROW_ESTIMATE = 56;

interface Meta {
  total: number;
  policyName: string;
}

/** Page cache for one query (``base``); a different query starts from an empty cache. */
interface Cache {
  base: string | null;
  pages: Map<number, RuleRow[]>;
  meta: Meta | null;
  error: string | null;
}

const emptyCache = (base: string | null): Cache => ({ base, pages: new Map(), meta: null, error: null });

/**
 * The rulebase exactly as in the FMC: original order, sections and categories.
 * Rows are fetched page by page as they scroll into view (10K+ rules per policy).
 */
export function RulebasePage() {
  const { t, tError } = useI18n();
  const { snapshots, snapshotId, setSnapshotId, error: snapError } = useSnapshotSelection();
  const [clusterParam, setClusterParam] = useQueryParam('cluster');
  const [qParam, setQParam] = useQueryParam('q');
  const [search, setSearch] = useState(qParam ?? '');
  const clusters = useApi<Cluster[]>(snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}/clusters`);
  const withPolicy = (clusters.data ?? []).filter((c) => c.policy_fmc_id !== null);
  const cluster = withPolicy.find((c) => c.fmc_id === clusterParam) ?? withPolicy[0] ?? null;
  const policyId = cluster?.policy_fmc_id ?? null;

  const [cache, setCache] = useState<Cache>(() => emptyCache(null));
  const requested = useRef<{ base: string | null; pages: Set<number> }>({ base: null, pages: new Set() });
  const scrollRef = useRef<HTMLDivElement>(null);

  // Debounced search -> URL.
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setQParam(search.trim() === '' ? null : search.trim());
    }, 300);
    return () => {
      window.clearTimeout(timer);
    };
  }, [search, setQParam]);

  const base = useMemo(() => {
    if (snapshotId === null || policyId === null) return null;
    const q = qParam !== null ? `&q=${encodeURIComponent(qParam)}` : '';
    return `/api/snapshots/${String(snapshotId)}/policies/${encodeURIComponent(policyId)}/rules?limit=${String(PAGE)}${q}`;
  }, [snapshotId, policyId, qParam]);

  const current = cache.base === base ? cache : emptyCache(base);
  const { pages, meta, error } = current;

  const loadPage = useMemo(
    () => (page: number) => {
      if (base === null) return;
      if (requested.current.base !== base) requested.current = { base, pages: new Set() };
      if (requested.current.pages.has(page)) return;
      requested.current.pages.add(page);
      const forBase = (prev: Cache): Cache => (prev.base === base ? prev : emptyCache(base));
      api<RulesPage>(`${base}&offset=${String(page * PAGE)}`)
        .then((data) => {
          setCache((prev) => {
            const c = forBase(prev);
            return {
              ...c,
              meta: { total: data.total, policyName: data.policy_name },
              pages: new Map(c.pages).set(page, data.rows),
            };
          });
        })
        .catch((err: unknown) => {
          requested.current.pages.delete(page);
          setCache((prev) => ({ ...forBase(prev), error: errorCode(err) }));
        });
    },
    [base],
  );

  useEffect(() => {
    loadPage(0);
  }, [loadPage]);

  const total = meta?.total ?? 0;
  // TanStack Virtual is used exactly as documented; this component does not rely on
  // React Compiler memoization, which is what the rule warns about.
  // eslint-disable-next-line react-hooks/incompatible-library
  const virtualizer = useVirtualizer({
    count: total,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_ESTIMATE,
    overscan: 12,
    initialRect: { width: 1200, height: 800 },
  });
  const items = virtualizer.getVirtualItems();
  const first = items[0]?.index ?? 0;
  const last = items[items.length - 1]?.index ?? 0;

  useEffect(() => {
    if (total === 0) return;
    for (let page = Math.floor(first / PAGE); page <= Math.floor(last / PAGE); page += 1) {
      loadPage(page);
    }
  }, [first, last, total, loadPage]);

  const rowAt = (index: number): RuleRow | undefined => pages.get(Math.floor(index / PAGE))?.[index % PAGE];

  return (
    <div className="stack">
      <div className="row spread">
        <h1>{t('rules.title')}</h1>
        <SnapshotPicker snapshots={snapshots} value={snapshotId} onChange={setSnapshotId} />
      </div>
      {snapError !== null && <Alert kind="error">{tError(snapError)}</Alert>}
      {snapshotId === null && snapError === null && <Alert kind="info">{t('snap.none')}</Alert>}
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}

      {withPolicy.length > 0 && (
        <div className="row">
          <label className="inline-field">
            {t('rules.cluster')}
            <select
              value={cluster?.fmc_id ?? ''}
              onChange={(e) => {
                setClusterParam(e.target.value);
              }}
            >
              {withPolicy.map((c) => (
                <option key={c.fmc_id} value={c.fmc_id}>
                  {c.name} — {c.policy_name}
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
              placeholder={t('rules.search')}
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
              }}
            />
          </label>
          {meta !== null && (
            <span className="muted">
              <Ltr>{meta.policyName}</Ltr> · {t('rules.count', { count: total })}
            </span>
          )}
        </div>
      )}

      {snapshotId !== null && meta !== null && (
        <div className="rulebase card">
          <div className="rule-grid rule-head" role="row">
            <span>{t('rules.col.index')}</span>
            <span>{t('rules.col.name')}</span>
            <span>{t('rules.col.srcZone')}</span>
            <span>{t('rules.col.srcNet')}</span>
            <span>{t('rules.col.dstZone')}</span>
            <span>{t('rules.col.dstNet')}</span>
            <span>{t('rules.col.service')}</span>
            <span>{t('rules.col.action')}</span>
            <span>{t('rules.col.hits')}</span>
          </div>
          <div ref={scrollRef} className="rule-scroll" role="table" aria-rowcount={total}>
            <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
              {items.map((item) => {
                const rule = rowAt(item.index);
                const prev = item.index > 0 ? rowAt(item.index - 1) : undefined;
                const band =
                  rule !== undefined &&
                  (item.index === 0 || prev?.section !== rule.section || prev.category !== rule.category);
                return (
                  <div
                    key={item.key}
                    data-index={item.index}
                    ref={virtualizer.measureElement}
                    className="rule-row-wrap"
                    style={{ transform: `translateY(${String(item.start)}px)` }}
                  >
                    {band && (
                      <div className="rule-band">
                        {t('rules.section', { name: rule.section })} · <Ltr>{rule.category}</Ltr>
                      </div>
                    )}
                    {rule === undefined ? (
                      <div className="rule-grid rule-row placeholder">…</div>
                    ) : (
                      <RuleLine rule={rule} snapshotId={snapshotId} />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function RuleLine({ rule, snapshotId }: { rule: RuleRow; snapshotId: number }) {
  const { t } = useI18n();
  const service = [...(rule.refs.dst_port ?? []), ...(rule.refs.app ?? []), ...(rule.refs.url ?? [])];
  return (
    <div className={`rule-grid rule-row${rule.enabled ? '' : ' disabled'}`} role="row">
      <span>{rule.index}</span>
      <span>
        <Ltr>{rule.name}</Ltr>
        {!rule.enabled && <span className="badge">{t('rules.disabled')}</span>}
        {rule.ips_policy !== null && (
          <div className="muted small">{t('rules.ips', { name: rule.ips_policy })}</div>
        )}
      </span>
      <span>
        <RefList items={rule.refs.src_zone} snapshotId={snapshotId} />
      </span>
      <span>
        <RefList items={[...(rule.refs.src_net ?? []), ...(rule.refs.src_sgt ?? []), ...(rule.refs.src_dyn ?? [])]} snapshotId={snapshotId} />
      </span>
      <span>
        <RefList items={rule.refs.dst_zone} snapshotId={snapshotId} />
      </span>
      <span>
        <RefList items={[...(rule.refs.dst_net ?? []), ...(rule.refs.dst_sgt ?? []), ...(rule.refs.dst_dyn ?? [])]} snapshotId={snapshotId} />
      </span>
      <span>
        <RefList items={service} snapshotId={snapshotId} />
      </span>
      <span className={`action action-${rule.action.toLowerCase()}`}>{rule.action}</span>
      <span className={rule.hit_count === 0 ? 'bad' : ''}>{rule.hit_count ?? '—'}</span>
    </div>
  );
}
