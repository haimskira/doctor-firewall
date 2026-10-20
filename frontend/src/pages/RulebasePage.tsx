import { useVirtualizer } from '@tanstack/react-virtual';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { api, errorCode } from '../api/client';
import { RULE_POLICY_KINDS } from '../api/types';
import type { Cluster, PolicyKind, RefItem, RuleFieldName, RuleGroup, RuleRow, RulesPage } from '../api/types';
import { Alert, Ltr } from '../components/common';
import {
  AllowIcon,
  ArrowBack,
  ArrowRight,
  BlockIcon,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  EmptyCircle,
  EyeIcon,
  FileIcon,
  FilterIcon,
  LockIcon,
  LogIcon,
  ShieldIcon,
} from '../components/icons';
import { RefList, SnapshotPicker } from '../components/inventory';
import { RecTag } from '../components/recommendations';
import { ReasonList, ScoreBadge } from '../components/score';
import { useApi, useQueryParam, useSnapshotSelection } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';
import type { MessageKey } from '../i18n/messages';

const PAGE = 200;
const ROW_ESTIMATE = 56;
const BAND_ESTIMATE = 34;
/** Height of the sticky two-level table header (kept in sync with ``.pe-head`` in styles.css). */
const HEADER_HEIGHT = 60;
/** Values shown per cell before the "+N more" toggle. */
const CELL_LIMIT = 2;

/** The FMC policy flow, in evaluation order. */
const FLOW: readonly PolicyKind[] = ['prefilter', 'decryption', 'identity', 'access', 'nat'];

const SECTION_LABELS = new Map<string, MessageKey>(Object.entries({
  Mandatory: 'section.mandatory',
  Default: 'section.default',
  BEFORE_AUTO: 'section.natBefore',
  AUTO: 'section.natAuto',
  AFTER_AUTO: 'section.natAfter',
} satisfies Record<string, MessageKey>));

const ACTION_LABELS = new Map<string, MessageKey>(Object.entries({
  ALLOW: 'action.allow',
  TRUST: 'action.trust',
  BLOCK: 'action.block',
  BLOCK_RESET: 'action.blockReset',
  BLOCK_INTERACTIVE: 'action.blockInteractive',
  BLOCK_RESET_INTERACTIVE: 'action.blockResetInteractive',
  MONITOR: 'action.monitor',
  FASTPATH: 'action.fastpath',
  ANALYZE: 'action.analyze',
  DO_NOT_DECRYPT: 'action.doNotDecrypt',
  DECRYPT_RESIGN: 'action.decryptResign',
  DECRYPT_KNOWN_KEY: 'action.decryptKnownKey',
  PERMIT: 'action.allow',
} satisfies Record<string, MessageKey>));

interface Meta {
  total: number;
  policyName: string;
  kind: PolicyKind;
  defaultAction: string;
  groups: RuleGroup[];
}

/** Page cache for one query (``base``); a different query starts from an empty cache. */
interface Cache {
  base: string | null;
  pages: Map<number, RuleRow[]>;
  meta: Meta | null;
  error: string | null;
  collapsed: Set<number>;
}

const emptyCache = (base: string | null): Cache => ({
  base,
  pages: new Map(),
  meta: null,
  error: null,
  collapsed: new Set(),
});

/** One line of the virtual list: a section band or a rule (by position in the ordered list). */
type Entry = { kind: 'band'; group: RuleGroup } | { kind: 'row'; position: number };

function buildEntries(total: number, groups: RuleGroup[], collapsed: Set<number>): Entry[] {
  if (groups.length === 0) {
    return Array.from({ length: total }, (_, position) => ({ kind: 'row', position }));
  }
  const out: Entry[] = [];
  for (const group of groups) {
    out.push({ kind: 'band', group });
    if (collapsed.has(group.start)) continue;
    for (let i = 0; i < group.count; i += 1) out.push({ kind: 'row', position: group.start + i });
  }
  return out;
}

/**
 * The FMC Policy Editor (read-only): the policy flow tabs of the selected cluster, then the
 * rulebase exactly as in the FMC — original order, collapsible section/category bands.
 * Rows are fetched page by page as they scroll into view (10K+ rules per policy).
 */
export function RulebasePage() {
  const { t, tError } = useI18n();
  const { snapshots, snapshotId, setSnapshotId, error: snapError } = useSnapshotSelection();
  const [clusterParam, setClusterParam] = useQueryParam('cluster');
  const [policyParam, setPolicyParam] = useQueryParam('policy');
  const [qParam, setQParam] = useQueryParam('q');
  const [search, setSearch] = useState(qParam ?? '');
  const clusters = useApi<Cluster[]>(snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}/clusters`);
  const withPolicy = (clusters.data ?? []).filter((c) => c.policies.length > 0);
  const cluster = withPolicy.find((c) => c.fmc_id === clusterParam) ?? withPolicy[0] ?? null;
  // Rule-bearing policies governing the cluster (access, prefilter, NAT, ...).
  const choices = (cluster?.policies ?? []).filter((p) => RULE_POLICY_KINDS.includes(p.kind));
  // ``?policy=`` also opens policies not linked to any cluster (e.g. from the Policies page).
  const policyId = policyParam ?? choices.find((p) => p.kind === 'access')?.id ?? choices[0]?.id ?? null;
  const targeted = (clusters.data ?? []).filter((c) => c.policies.some((p) => p.id === policyId)).length;

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
  const { pages, meta, error, collapsed } = current;

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
              // Section runs come with the first page only; later pages keep them.
              meta: {
                total: data.total,
                policyName: data.policy_name,
                kind: data.policy_kind,
                defaultAction: data.default_action,
                groups: page === 0 ? data.groups : (c.meta?.groups ?? []),
              },
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
  const entries = useMemo(() => buildEntries(total, meta?.groups ?? [], collapsed), [total, meta, collapsed]);

  function toggleBand(start: number) {
    setCache((prev) => {
      const c = prev.base === base ? prev : emptyCache(base);
      const next = new Set(c.collapsed);
      if (next.has(start)) next.delete(start);
      else next.add(start);
      return { ...c, collapsed: next };
    });
  }

  // TanStack Virtual is used exactly as documented; this component does not rely on
  // React Compiler memoization, which is what the rule warns about.
  // eslint-disable-next-line react-hooks/incompatible-library
  const virtualizer = useVirtualizer({
    count: entries.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: (i) => (entries.at(i)?.kind === 'band' ? BAND_ESTIMATE : ROW_ESTIMATE),
    getItemKey: (i) => {
      const entry = entries.at(i);
      if (entry === undefined) return `x${String(i)}`;
      return entry.kind === 'band' ? `b${String(entry.group.start)}` : `r${String(entry.position)}`;
    },
    overscan: 12,
    scrollMargin: HEADER_HEIGHT,
    initialRect: { width: 1200, height: 800 },
  });
  const items = virtualizer.getVirtualItems();
  const visibleRows = items.flatMap((item) => {
    const entry = entries.at(item.index);
    return entry?.kind === 'row' ? [entry.position] : [];
  });
  const firstRow = visibleRows.length > 0 ? Math.min(...visibleRows) : 0;
  const lastRow = visibleRows.length > 0 ? Math.max(...visibleRows) : 0;

  useEffect(() => {
    if (total === 0) return;
    for (let page = Math.floor(firstRow / PAGE); page <= Math.floor(lastRow / PAGE); page += 1) {
      loadPage(page);
    }
  }, [firstRow, lastRow, total, loadPage]);

  const rowAt = (position: number): RuleRow | undefined => pages.get(Math.floor(position / PAGE))?.[position % PAGE];
  const activeKind = meta?.kind ?? choices.find((p) => p.id === policyId)?.kind ?? null;
  const isAccess = meta?.kind === 'access';

  return (
    <div className="pe">
      <Link className="pe-back" to={snapshotId === null ? '/policies' : `/policies?snapshot=${String(snapshotId)}`}>
        <ArrowBack size={16} className="flip-rtl" />
        {t('pe.back')}
      </Link>
      <div className="pe-title">
        <LockIcon size={18} />
        <h1>{meta !== null ? <Ltr>{meta.policyName}</Ltr> : t('rules.title')}</h1>
        <span className="pe-readonly">{t('pe.readOnly')}</span>
      </div>

      {snapError !== null && <Alert kind="error">{tError(snapError)}</Alert>}
      {snapshotId === null && snapError === null && <Alert kind="info">{t('snap.none')}</Alert>}
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}

      <div className="pe-context">
        <SnapshotPicker snapshots={snapshots} value={snapshotId} onChange={setSnapshotId} />
        {withPolicy.length > 0 && (
          <>
            <label className="inline-field">
              {t('rules.cluster')}
              <select
                value={cluster?.fmc_id ?? ''}
                onChange={(e) => {
                  setClusterParam(e.target.value);
                  setPolicyParam(null);
                }}
              >
                {withPolicy.map((c) => (
                  <option key={c.fmc_id} value={c.fmc_id}>
                    {c.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="inline-field">
              {t('rules.policy')}
              <select
                value={policyId ?? ''}
                onChange={(e) => {
                  setPolicyParam(e.target.value);
                }}
              >
                {choices.every((p) => p.id !== policyId) && policyId !== null && (
                  <option value={policyId}>{meta?.policyName ?? policyId}</option>
                )}
                {choices.map((p) => (
                  <option key={p.id} value={p.id}>
                    {t(`kind.${p.kind}`)}: {p.name} ({p.rule_count})
                  </option>
                ))}
              </select>
            </label>
          </>
        )}
      </div>

      {cluster !== null && (
        <div className="pe-flow" role="tablist" aria-label={t('pe.flow')}>
          {FLOW.map((kind, i) => {
            const policy = choices.find((p) => p.kind === kind);
            const selected = activeKind === kind && policy?.id === policyId;
            return (
              <span key={kind} className="pe-flow-step">
                {i > 0 && <ArrowRight size={14} className="pe-arrow flip-rtl" />}
                <button
                  type="button"
                  role="tab"
                  aria-selected={selected}
                  disabled={policy === undefined}
                  title={policy?.name ?? t('pe.none')}
                  className={selected ? 'active' : ''}
                  onClick={() => {
                    if (policy !== undefined) setPolicyParam(policy.id);
                  }}
                >
                  {policy !== undefined ? <CheckCircle size={16} className="ok" /> : <EmptyCircle size={16} className="muted" />}
                  {t(`kind.${kind}`)}
                </button>
              </span>
            );
          })}
          <span className="pe-targeted">{t('pe.targeted', { count: targeted })}</span>
        </div>
      )}

      {snapshotId !== null && meta !== null && (
        <section className="pe-table">
          <div className="pe-toolbar">
            <FilterIcon size={16} className="muted" />
            <input
              type="search"
              dir="auto"
              maxLength={128}
              placeholder={t('rules.search')}
              aria-label={t('common.search')}
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
              }}
            />
            <span className="pe-total">{t('pe.total', { count: total })}</span>
          </div>
          <div ref={scrollRef} className="pe-scroll" role="table" aria-rowcount={total}>
            <div className={`pe-inner${isAccess ? ' access' : ' generic'}`}>
              {isAccess ? <AccessHeader /> : <GenericHeader />}
              <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
                {items.map((item) => {
                  const entry = entries.at(item.index);
                  if (entry === undefined) return null;
                  const rule = entry.kind === 'row' ? rowAt(entry.position) : undefined;
                  return (
                    <div
                      key={item.key}
                      data-index={item.index}
                      ref={virtualizer.measureElement}
                      className="pe-entry"
                      style={{ transform: `translateY(${String(item.start - virtualizer.options.scrollMargin)}px)` }}
                    >
                      {entry.kind === 'band' ? (
                        <Band
                          group={entry.group}
                          open={!collapsed.has(entry.group.start)}
                          onToggle={() => {
                            toggleBand(entry.group.start);
                          }}
                        />
                      ) : rule === undefined ? (
                        <div className="pe-row placeholder">…</div>
                      ) : isAccess ? (
                        <AccessRow rule={rule} snapshotId={snapshotId} />
                      ) : (
                        <GenericRow rule={rule} snapshotId={snapshotId} />
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
          {meta.defaultAction !== '' && (
            <footer className="pe-footer">
              <span className="muted">{t('pe.defaultAction')}</span>
              <span className="pe-default">
                {t(`kind.${meta.kind}`)}: <ActionLabel action={meta.defaultAction} />
              </span>
            </footer>
          )}
        </section>
      )}
    </div>
  );
}

function SectionName({ section }: { section: string }) {
  const { t } = useI18n();
  const key = SECTION_LABELS.get(section);
  return key !== undefined ? <>{t(key)}</> : <Ltr>{section}</Ltr>;
}

/** A grey FMC section band: "Mandatory · Category  4 rules (1 - 4)", collapsible. */
function Band({ group, open, onToggle }: { group: RuleGroup; open: boolean; onToggle: () => void }) {
  const { t } = useI18n();
  return (
    <div className="pe-band" role="row">
      <button type="button" className="pe-band-toggle" aria-expanded={open} onClick={onToggle}>
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} className="flip-rtl" />}
        <strong>
          <SectionName section={group.section} />
        </strong>
        {group.category !== '' && <Ltr>{group.category}</Ltr>}
      </button>
      <span className="muted">
        {t('pe.band', { count: group.count, first: group.first_index, last: group.last_index })}
      </span>
    </div>
  );
}

/** Action as in the FMC: a coloured icon and the action name. */
function ActionLabel({ action }: { action: string }) {
  const { t } = useI18n();
  const upper = action.toUpperCase();
  const key = ACTION_LABELS.get(upper);
  let icon: ReactNode = null;
  let tone = 'neutral';
  if (upper === 'ALLOW' || upper === 'TRUST' || upper === 'PERMIT' || upper === 'FASTPATH') {
    icon = <AllowIcon size={15} />;
    tone = 'allow';
  } else if (upper.startsWith('BLOCK')) {
    icon = <BlockIcon size={15} />;
    tone = 'block';
  } else if (upper === 'MONITOR' || upper === 'ANALYZE') {
    icon = <EyeIcon size={15} />;
    tone = 'monitor';
  }
  return (
    <span className={`pe-action tone-${tone}`}>
      {icon}
      {key !== undefined ? t(key) : <Ltr>{action}</Ltr>}
    </span>
  );
}

function AccessHeader() {
  const { t } = useI18n();
  return (
    <div className="pe-head" role="row">
      <span className="h-index" role="columnheader">
        {t('rules.col.index')}
      </span>
      <span className="h-name" role="columnheader">
        {t('rules.col.name')}
      </span>
      <span className="h-action" role="columnheader">
        {t('rules.col.action')}
      </span>
      <span className="h-insp" role="columnheader">
        {t('pe.inspection')}
      </span>
      <span className="h-src group" role="columnheader">
        {t('pe.source')}
      </span>
      <span className="h-dst group" role="columnheader">
        {t('pe.destination')}
      </span>
      <span className="h-apps" role="columnheader">
        {t('pe.apps')}
      </span>
      <span className="h-hits" role="columnheader">
        {t('rules.col.hits')}
      </span>
      <span className="h-score" role="columnheader">
        {t('score.col')}
      </span>
      <span className="h-src-zone sub" role="columnheader">
        {t('pe.zones')}
      </span>
      <span className="h-src-net sub" role="columnheader">
        {t('pe.networks')}
      </span>
      <span className="h-dst-zone sub" role="columnheader">
        {t('pe.zones')}
      </span>
      <span className="h-dst-net sub" role="columnheader">
        {t('pe.networks')}
      </span>
      <span className="h-dst-port sub" role="columnheader">
        {t('pe.ports')}
      </span>
    </div>
  );
}

function GenericHeader() {
  const { t } = useI18n();
  return (
    <div className="pe-head generic" role="row">
      <span role="columnheader">{t('rules.col.index')}</span>
      <span role="columnheader">{t('rules.col.name')}</span>
      <span role="columnheader">{t('rules.col.type')}</span>
      <span role="columnheader">{t('rules.col.action')}</span>
      <span role="columnheader">{t('rules.col.match')}</span>
    </div>
  );
}

/** The change tags a rule carries (type + deploy cost), linking to the recommendation. */
function RecTags({ rule, snapshotId }: { rule: RuleRow; snapshotId: number }) {
  const tags = rule.recommendations ?? [];
  if (tags.length === 0) return null;
  return (
    <span className="rec-tags">
      {tags.map((tag) => (
        <RecTag key={tag.id} tag={tag} snapshotId={snapshotId} />
      ))}
    </span>
  );
}

/** IPS / file policy / logging indicators (coloured when on, grey when off). */
function Inspection({ rule }: { rule: RuleRow }) {
  const { t } = useI18n();
  const logging = rule.log_begin || rule.log_end;
  const ips = rule.ips_policy !== null ? t('pe.ips', { name: rule.ips_policy }) : t('pe.noIps');
  const file = rule.file_policy !== null ? t('pe.file', { name: rule.file_policy }) : t('pe.noFile');
  const log = logging ? t('pe.log') : t('pe.noLog');
  return (
    <span className="pe-insp">
      <span role="img" aria-label={ips} title={ips} className={rule.ips_policy !== null ? 'on' : 'off'}>
        <ShieldIcon size={15} />
      </span>
      <span role="img" aria-label={file} title={file} className={rule.file_policy !== null ? 'on' : 'off'}>
        <FileIcon size={15} />
      </span>
      <span role="img" aria-label={log} title={log} className={logging ? 'on' : 'off'}>
        <LogIcon size={15} />
      </span>
    </span>
  );
}

function AccessRow({ rule, snapshotId }: { rule: RuleRow; snapshotId: number }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const apps = [...(rule.refs.app ?? []), ...(rule.refs.url ?? [])];
  const cell = (items: RefItem[] | undefined) => <RefList items={items} snapshotId={snapshotId} limit={CELL_LIMIT} />;
  return (
    <div className={`pe-row access${rule.enabled ? '' : ' disabled'}`} role="row">
      <span className="c-index">{rule.index}</span>
      <span className="c-name">
        <Ltr>{rule.name}</Ltr>
        {!rule.enabled && <span className="badge">{t('rules.disabled')}</span>}
        <RecTags rule={rule} snapshotId={snapshotId} />
      </span>
      <span className="c-action">
        <ActionLabel action={rule.action} />
      </span>
      <span className="c-insp">
        <Inspection rule={rule} />
      </span>
      <span className="c-src-zone">{cell(rule.refs.src_zone)}</span>
      <span className="c-src-net">
        {cell([...(rule.refs.src_net ?? []), ...(rule.refs.src_sgt ?? []), ...(rule.refs.src_dyn ?? [])])}
      </span>
      <span className="c-dst-zone">{cell(rule.refs.dst_zone)}</span>
      <span className="c-dst-net">
        {cell([...(rule.refs.dst_net ?? []), ...(rule.refs.dst_sgt ?? []), ...(rule.refs.dst_dyn ?? [])])}
      </span>
      <span className="c-dst-port">{cell(rule.refs.dst_port)}</span>
      <span className="c-apps">{cell(apps)}</span>
      <span className={`c-hits${rule.hit_count === 0 ? ' bad' : ''}`}>{rule.hit_count ?? '—'}</span>
      <span className="c-score">
        <button
          type="button"
          className="link"
          aria-expanded={open}
          aria-label={`${t('score.reasons')}: ${rule.score === null || rule.score === undefined ? t('score.none') : String(rule.score)}`}
          onClick={() => {
            setOpen(!open);
          }}
        >
          <ScoreBadge score={rule.score} />
        </button>
        {(rule.shadowed_by ?? null) !== null && <span className="badge sev-high">{t('score.shadowed')}</span>}
        {rule.dead === true && <span className="badge sev-medium">{t('score.dead')}</span>}
        {rule.ace_count !== undefined && rule.ace_count !== null && rule.ace_count > 1 && (
          <span className="muted small">
            {rule.ace_count.toLocaleString()} {t('score.aces')}
          </span>
        )}
      </span>
      {open && (
        <div className="pe-reasons">
          <ReasonList reasons={rule.reasons ?? []} />
        </div>
      )}
    </div>
  );
}

/** Prefilter / decryption / identity / NAT rules: every populated field, labelled. */
function GenericRow({ rule, snapshotId }: { rule: RuleRow; snapshotId: number }) {
  const { t } = useI18n();
  const fields = Object.entries(rule.refs) as [RuleFieldName, RefItem[]][];
  return (
    <div className={`pe-row generic${rule.enabled ? '' : ' disabled'}`} role="row">
      <span>{rule.index}</span>
      <span>
        <Ltr>{rule.name}</Ltr>
        {!rule.enabled && <span className="badge">{t('rules.disabled')}</span>}
        <RecTags rule={rule} snapshotId={snapshotId} />
      </span>
      <span>
        <Ltr>{rule.rule_type ?? rule.section}</Ltr>
      </span>
      <span>
        <ActionLabel action={rule.action} />
      </span>
      <span className="match-fields">
        {fields.length === 0 ? (
          <span className="muted">{t('rules.any')}</span>
        ) : (
          fields.map(([field, items]) => (
            <span key={field} className="match-field">
              <span className="muted small">{t(`field.${field}`)}:</span>{' '}
              <RefList items={items} snapshotId={snapshotId} limit={CELL_LIMIT} />
            </span>
          ))
        )}
      </span>
    </div>
  );
}
