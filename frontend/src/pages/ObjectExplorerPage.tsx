import { CaretDownIcon, CaretRightIcon, ArrowSquareInIcon, WarningIcon } from '@phosphor-icons/react';
import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { api, errorCode } from '../api/client';
import type { FwObject, ObjectDetail, ObjectRelations, ObjectsPage } from '../api/types';
import { Alert, Ltr } from '../components/common';
import { SnapshotPicker } from '../components/inventory';
import { useApi, useQueryParam, useSnapshotSelection } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';
import type { MessageKey } from '../i18n/messages';

const KINDS = ['host', 'network', 'range', 'fqdn', 'network_group', 'port', 'port_group', 'url', 'url_group'] as const;
const SEARCH_PAGE = 50;
const OVERLAP_KEYS = new Map<string, MessageKey>([
  ['same', 'explorer.overlap.same'],
  ['contains', 'explorer.overlap.contains'],
  ['within', 'explorer.overlap.within'],
  ['overlaps', 'explorer.overlap.overlaps'],
]);
const TREE_PAGE = 100;

export interface TreeNode {
  id: string | null;
  name: string;
  kind: string;
  value: string | null;
  members: number;
  member_of: number;
  rule_refs: number;
  read_only: boolean;
}

interface TreePage {
  parent: string;
  direction: 'up' | 'down';
  total: number;
  offset: number;
  nodes: TreeNode[];
}

type Direction = 'up' | 'down';

/**
 * Object explorer: pick any object (or group) and walk the tree around it — the groups holding
 * it, level by level, and its members — one level at a time, so even very large trees stay light.
 * The side panel explains the selected node: value, rules using it (and through which level),
 * redundant links with their fix, overlapping objects.
 */
export function ObjectExplorerPage() {
  const { t, tError } = useI18n();
  const { snapshots, snapshotId, setSnapshotId, error: snapError } = useSnapshotSelection();
  const [rootId, setRootId] = useQueryParam('object');
  const [selected, setSelected] = useState<string | null>(rootId);
  const [history, setHistory] = useState<{ id: string; name: string }[]>([]);
  const root = useApi<ObjectDetail>(
    snapshotId === null || rootId === null
      ? null
      : `/api/snapshots/${String(snapshotId)}/objects/${encodeURIComponent(rootId)}`,
  );

  const open = useCallback(
    (id: string) => {
      if (rootId !== null && root.data !== null) {
        const previous = { id: rootId, name: root.data.object.name };
        setHistory((h) => [...h, previous].slice(-8));
      }
      setRootId(id);
      setSelected(id);
    },
    [rootId, root.data, setRootId],
  );

  return (
    <div className="stack explorer-page">
      <div className="row spread">
        <div>
          <h1>{t('explorer.title')}</h1>
          <p className="muted small">{t('explorer.help')}</p>
        </div>
        <SnapshotPicker snapshots={snapshots} value={snapshotId} onChange={setSnapshotId} />
      </div>
      {snapError !== null && <Alert kind="error">{tError(snapError)}</Alert>}
      {snapshotId !== null && (
        <div className="explorer">
          <ObjectSearch
            snapshotId={snapshotId}
            current={rootId}
            onPick={(o) => {
              open(o.id);
            }}
          />
          <section className="card explorer-tree" aria-label={t('explorer.tree')}>
            {history.length > 0 && (
              <nav className="explorer-crumbs small" aria-label={t('explorer.history')}>
                {history.map((h, i) => (
                  <button
                    key={`${h.id}-${String(i)}`}
                    type="button"
                    className="link"
                    onClick={() => {
                      setHistory(history.slice(0, i));
                      setRootId(h.id);
                      setSelected(h.id);
                    }}
                  >
                    <Ltr>{h.name}</Ltr>
                  </button>
                ))}
                <span aria-hidden="true">›</span>
              </nav>
            )}
            {rootId === null ? (
              <p className="muted">{t('explorer.pick')}</p>
            ) : root.error !== null ? (
              <Alert kind="error">{tError(root.error)}</Alert>
            ) : root.data === null ? (
              <p className="muted">{t('common.loading')}</p>
            ) : (
              <ExplorerTree
                key={`${String(snapshotId)}-${rootId}`}
                snapshotId={snapshotId}
                root={root.data.object}
                selected={selected}
                onSelect={setSelected}
              />
            )}
          </section>
          <section className="card explorer-detail" aria-live="polite">
            {selected === null ? (
              <p className="muted">{t('explorer.selectNode')}</p>
            ) : (
              <NodeDetail
                key={selected}
                snapshotId={snapshotId}
                objectId={selected}
                isRoot={selected === rootId}
                onExplore={(id) => {
                  open(id);
                }}
              />
            )}
          </section>
        </div>
      )}
    </div>
  );
}

function ObjectSearch({
  snapshotId,
  current,
  onPick,
}: {
  snapshotId: number;
  current: string | null;
  onPick: (o: FwObject) => void;
}) {
  const { t, tError } = useI18n();
  const [text, setText] = useState('');
  const [query, setQuery] = useState('');
  const [kind, setKind] = useState('');
  const [rows, setRows] = useState<FwObject[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setQuery(text.trim());
    }, 250);
    return () => {
      window.clearTimeout(timer);
    };
  }, [text]);

  const url = useCallback(
    (offset: number) => {
      const params = new URLSearchParams({ offset: String(offset), limit: String(SEARCH_PAGE) });
      if (query !== '') params.set('q', query);
      if (kind !== '') params.set('kind', kind);
      return `/api/snapshots/${String(snapshotId)}/objects?${params.toString()}`;
    },
    [snapshotId, query, kind],
  );

  useEffect(() => {
    let cancelled = false;
    api<ObjectsPage>(url(0))
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
  }, [url]);

  return (
    <section className="card explorer-search" aria-label={t('explorer.search')}>
      <input
        type="search"
        dir="auto"
        maxLength={128}
        placeholder={t('explorer.searchPlaceholder')}
        aria-label={t('explorer.search')}
        value={text}
        onChange={(e) => {
          setText(e.target.value);
        }}
      />
      <select
        aria-label={t('objects.col.kind')}
        value={kind}
        onChange={(e) => {
          setKind(e.target.value);
        }}
      >
        <option value="">{t('explorer.allKinds')}</option>
        {KINDS.map((k) => (
          <option key={k} value={k}>
            {k}
          </option>
        ))}
      </select>
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      <p className="muted small">{t('explorer.results', { count: total })}</p>
      <ul className="explorer-results">
        {rows.map((o) => (
          <li key={o.id}>
            <button
              type="button"
              className={`explorer-result${o.id === current ? ' active' : ''}`}
              aria-pressed={o.id === current}
              onClick={() => {
                onPick(o);
              }}
            >
              <span className="name">
                <Ltr>{o.name}</Ltr>
              </span>
              <span className="muted small">
                {o.kind}
                {o.value !== null && (
                  <>
                    {' · '}
                    <Ltr>{o.value}</Ltr>
                  </>
                )}
              </span>
            </button>
          </li>
        ))}
      </ul>
      {rows.length < total && (
        <button
          type="button"
          className="secondary"
          onClick={() => {
            void api<ObjectsPage>(url(rows.length)).then((page) => {
              setRows((r) => [...r, ...page.rows]);
            });
          }}
        >
          {t('explorer.more', { count: total - rows.length })}
        </button>
      )}
    </section>
  );
}

function ExplorerTree({
  snapshotId,
  root,
  selected,
  onSelect,
}: {
  snapshotId: number;
  root: FwObject;
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const { t } = useI18n();
  const node: TreeNode = {
    id: root.id,
    name: root.name,
    kind: root.kind,
    value: root.value,
    members: 0,
    member_of: root.member_of,
    rule_refs: root.rule_refs,
    read_only: false,
  };
  return (
    <div className="tree" role="tree" aria-label={root.name}>
      <div className="tree-root">
        <button
          type="button"
          className={`tree-label root${selected === root.id ? ' selected' : ''}`}
          onClick={() => {
            onSelect(root.id);
          }}
        >
          <NodeLabel node={node} />
        </button>
      </div>
      <h3 className="tree-heading">{t('explorer.up')}</h3>
      <Children snapshotId={snapshotId} parent={root.id} direction="up" path={[root.id]} selected={selected} onSelect={onSelect} />
      <h3 className="tree-heading">{t('explorer.down')}</h3>
      <Children snapshotId={snapshotId} parent={root.id} direction="down" path={[root.id]} selected={selected} onSelect={onSelect} />
    </div>
  );
}

function NodeLabel({ node }: { node: TreeNode }) {
  const { t } = useI18n();
  return (
    <>
      <span className={`kind-dot kind-${node.kind}`} aria-hidden="true" />
      <span className="tree-name">
        <Ltr>{node.name}</Ltr>
      </span>
      {node.value !== null && node.value !== node.name && (
        <span className="muted small tree-value">
          <Ltr>{node.value}</Ltr>
        </span>
      )}
      {node.rule_refs > 0 && <span className="badge tree-badge">{t('explorer.rulesBadge', { count: node.rule_refs })}</span>}
      {node.read_only && <span className="badge muted">{t('explorer.builtin')}</span>}
    </>
  );
}

/** One level, loaded on demand and paged. */
function Children({
  snapshotId,
  parent,
  direction,
  path,
  selected,
  onSelect,
}: {
  snapshotId: number;
  parent: string;
  direction: Direction;
  path: string[];
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const { t, tError } = useI18n();
  const [nodes, setNodes] = useState<TreeNode[] | null>(null);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    (offset: number) =>
      api<TreePage>(
        `/api/snapshots/${String(snapshotId)}/objects/${encodeURIComponent(parent)}/tree?direction=${direction}&offset=${String(offset)}&limit=${String(TREE_PAGE)}`,
      ),
    [snapshotId, parent, direction],
  );

  useEffect(() => {
    let cancelled = false;
    load(0)
      .then((page) => {
        if (cancelled) return;
        setNodes(page.nodes);
        setTotal(page.total);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorCode(err));
      });
    return () => {
      cancelled = true;
    };
  }, [load]);

  if (error !== null) return <Alert kind="error">{tError(error)}</Alert>;
  if (nodes === null) return <p className="muted small tree-pad">{t('common.loading')}</p>;
  if (nodes.length === 0) {
    return <p className="muted small tree-pad">{t(direction === 'up' ? 'explorer.noParents' : 'explorer.noMembers')}</p>;
  }
  return (
    <ul className="tree-level" role="group">
      {nodes.map((n, i) => (
        <TreeItem
          key={`${n.id ?? n.name}-${String(i)}`}
          snapshotId={snapshotId}
          node={n}
          direction={direction}
          path={path}
          selected={selected}
          onSelect={onSelect}
        />
      ))}
      {nodes.length < total && (
        <li>
          <button
            type="button"
            className="link small"
            onClick={() => {
              void load(nodes.length).then((page) => {
                setNodes([...nodes, ...page.nodes]);
              });
            }}
          >
            {t('explorer.more', { count: total - nodes.length })}
          </button>
        </li>
      )}
    </ul>
  );
}

function TreeItem({
  snapshotId,
  node,
  direction,
  path,
  selected,
  onSelect,
}: {
  snapshotId: number;
  node: TreeNode;
  direction: Direction;
  path: string[];
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const further = direction === 'up' ? node.member_of : node.members;
  const cycle = node.id !== null && path.includes(node.id);
  const expandable = node.id !== null && further > 0 && !cycle;
  return (
    <li role="treeitem" aria-expanded={expandable ? open : undefined} aria-selected={selected === node.id}>
      <div className="tree-row">
        {expandable ? (
          <button
            type="button"
            className="tree-toggle"
            aria-label={t(open ? 'explorer.collapse' : 'explorer.expand', { name: node.name })}
            onClick={() => {
              setOpen(!open);
            }}
          >
            {open ? <CaretDownIcon size={12} /> : <CaretRightIcon size={12} className="flip-rtl" />}
          </button>
        ) : (
          <span className="tree-toggle placeholder" aria-hidden="true" />
        )}
        <button
          type="button"
          className={`tree-label${selected === node.id ? ' selected' : ''}`}
          disabled={node.id === null}
          onClick={() => {
            if (node.id !== null) onSelect(node.id);
          }}
        >
          <NodeLabel node={node} />
          {expandable && <span className="muted small tree-count">({further})</span>}
          {cycle && (
            <span className="badge risk-badge risk-red" title={t('explorer.cycle')}>
              <WarningIcon size={11} aria-hidden="true" /> {t('explorer.cycleShort')}
            </span>
          )}
        </button>
      </div>
      {open && node.id !== null && (
        <Children
          snapshotId={snapshotId}
          parent={node.id}
          direction={direction}
          path={[...path, node.id]}
          selected={selected}
          onSelect={onSelect}
        />
      )}
    </li>
  );
}

function NodeDetail({
  snapshotId,
  objectId,
  isRoot,
  onExplore,
}: {
  snapshotId: number;
  objectId: string;
  isRoot: boolean;
  onExplore: (id: string) => void;
}) {
  const { t, tError } = useI18n();
  const base = `/api/snapshots/${String(snapshotId)}/objects/${encodeURIComponent(objectId)}`;
  const detail = useApi<ObjectDetail>(`${base}?limit=200`);
  const relations = useApi<ObjectRelations>(`${base}/relations`);
  const d = detail.data;
  if (detail.error !== null) return <Alert kind="error">{tError(detail.error)}</Alert>;
  if (d === null) return <p className="muted">{t('common.loading')}</p>;
  const byVia = new Map<string, typeof d.used_by>();
  for (const u of d.used_by) {
    const key = u.via_id === d.object.id ? '' : u.via_name;
    byVia.set(key, [...(byVia.get(key) ?? []), u]);
  }
  const overlaps = (relations.data?.nodes ?? []).filter((n) => n.role === 'overlap');
  const overlapLabel = new Map((relations.data?.edges ?? []).filter((e) => e.kind === 'overlap').map((e) => [e.target, e.label]));
  return (
    <div className="stack">
      <div>
        <h2>
          <Ltr>{d.object.name}</Ltr>
        </h2>
        <p className="muted small">
          {d.object.kind}
          {d.object.value !== null && (
            <>
              {' · '}
              <Ltr>{d.object.value}</Ltr>
            </>
          )}
        </p>
        <div className="row">
          {!isRoot && (
            <button
              type="button"
              className="secondary"
              onClick={() => {
                onExplore(d.object.id);
              }}
            >
              <ArrowSquareInIcon size={14} aria-hidden="true" /> {t('explorer.exploreHere')}
            </button>
          )}
          <Link to={`/objects/${encodeURIComponent(d.object.id)}?snapshot=${String(snapshotId)}`}>{t('explorer.fullDetail')}</Link>
        </div>
      </div>

      {(relations.data?.issues ?? []).length > 0 && (
        <div className="alert alert-info" role="note">
          <strong>{t('relations.issues', { count: relations.data?.issues.length ?? 0 })}</strong>
          <ul className="plain-list small">
            {(relations.data?.issues ?? []).map((issue) => (
              <li key={`${issue.kind}-${issue.where_id}-${issue.removed}`}>
                {t(`relations.issue.${issue.kind}`, { where: issue.where_name, removed: issue.removed, kept: issue.kept })}{' '}
                {issue.recommendation_id !== null && (
                  <Link to={`/recommendations?snapshot=${String(snapshotId)}&rec=${String(issue.recommendation_id)}`}>
                    {t('relations.fix')}
                  </Link>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div>
        <h3>{t('object.usedBy', { count: d.used_by_total })}</h3>
        {d.used_by.length === 0 ? (
          <p className="muted small">{t('explorer.unusedByRules')}</p>
        ) : (
          [...byVia.entries()].map(([via, uses]) => (
            <div key={via || 'direct'} className="explorer-usage">
              <p className="small muted">{via === '' ? t('object.direct') : t('explorer.via', { name: via })}</p>
              <ul className="plain-list small">
                {uses.map((u) => (
                  <li key={`${u.policy_fmc_id}-${u.rule_id}-${u.field}`}>
                    <Link
                      to={`/rules?snapshot=${String(snapshotId)}&policy=${encodeURIComponent(u.policy_fmc_id)}&q=${encodeURIComponent(u.rule_name)}`}
                    >
                      #{u.rule_index} <Ltr>{u.rule_name}</Ltr>
                    </Link>{' '}
                    <span className="muted">
                      {u.policy_name} · {t(`field.${u.field}`)}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ))
        )}
        {d.used_by_total > d.used_by.length && (
          <p className="muted small">{t('explorer.moreRules', { count: d.used_by_total - d.used_by.length })}</p>
        )}
      </div>

      {overlaps.length > 0 && (
        <div>
          <h3>{t('explorer.overlaps')}</h3>
          <ul className="plain-list small">
            {overlaps.map((o) => (
              <li key={o.id}>
                <button
                  type="button"
                  className="link"
                  onClick={() => {
                    onExplore(o.id);
                  }}
                >
                  <Ltr>{o.label}</Ltr>
                </button>{' '}
                <span className="muted">
                  <Ltr>{o.detail}</Ltr> · {t(OVERLAP_KEYS.get(overlapLabel.get(o.id) ?? '') ?? 'explorer.overlap.overlaps')}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
