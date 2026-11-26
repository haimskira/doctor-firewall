import { PlusIcon } from '@phosphor-icons/react';
import { Fragment, useState } from 'react';
import type { SyntheticEvent } from 'react';

import { api } from '../api/client';
import { SEGMENT_ROLES, TIERS } from '../api/types';
import type { AssetDomain, AssetGroup, Evidence, Segment, SegmentRole, Tier } from '../api/types';
import { useI18n } from '../i18n/I18nProvider';
import type { MessageKey } from '../i18n/messages';
import { Ltr } from './common';
import { SortedTable } from './sort';

/** Runs an action, shows its success text (or the translated error) and reloads the page's data. */
export type Run = (action: () => Promise<string>) => Promise<void>;

const PAGE = 50;
export const DELETE_WORD = 'DELETE';

export interface PurgeRequest {
  /** Endpoint that receives ``{ scope, confirm }``. */
  path: string;
  scope: string;
  text: MessageKey;
  /** Runs after a successful purge (for example, discovery again). */
  after?: () => Promise<string>;
}

/** A modal that asks for the word DELETE before it lets a destructive request go out. */
export function ConfirmDelete({ text, onCancel, onConfirm }: { text: string; onCancel: () => void; onConfirm: () => void }) {
  const { t } = useI18n();
  const [typed, setTyped] = useState('');
  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-modal="true" aria-label={t('disc.dialog.title')}>
        <h2>{t('disc.dialog.title')}</h2>
        <p>{text}</p>
        <label>
          {t('disc.dialog.type')}
          <input
            dir="ltr"
            autoFocus
            autoComplete="off"
            value={typed}
            onChange={(e) => {
              setTyped(e.target.value);
            }}
          />
        </label>
        <div className="row">
          <button type="button" className="danger" disabled={typed !== DELETE_WORD} onClick={onConfirm}>
            {t('disc.dialog.confirm')}
          </button>
          <button type="button" className="secondary" onClick={onCancel}>
            {t('disc.dialog.cancel')}
          </button>
        </div>
      </div>
    </div>
  );
}

/** Sends a purge request once the typed confirmation is given. */
export function PurgeDialog({ request, run, onClose }: { request: PurgeRequest | null; run: Run; onClose: () => void }) {
  const { t } = useI18n();
  if (request === null) return null;
  return (
    <ConfirmDelete
      text={t(request.text)}
      onCancel={onClose}
      onConfirm={() => {
        onClose();
        void run(async () => {
          const r = await api<{ deleted: number }>(request.path, 'POST', { scope: request.scope, confirm: DELETE_WORD });
          if (request.after !== undefined) return request.after();
          return t('disc.deletedCount', { count: r.deleted });
        });
      }}
    />
  );
}

const SOURCE_KEYS = new Map<string, MessageKey>([
  ['interface', 'disc.ev.interface'],
  ['route', 'disc.ev.route'],
  ['names', 'disc.ev.names'],
  ['behaviour', 'disc.ev.behaviour'],
  ['identity', 'disc.ev.identity'],
  ['composition', 'disc.ev.composition'],
  ['consensus', 'disc.ev.consensus'],
  ['group', 'disc.ev.group'],
  ['topology', 'disc.ev.topology'],
  ['default', 'disc.ev.default'],
]);

export function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  const { t } = useI18n();
  if (evidence.length === 0) return <p className="muted small">{t('disc.noEvidence')}</p>;
  return (
    <ul className="evidence-list small">
      {evidence.map((e, i) => {
        const key = SOURCE_KEYS.get(e.source);
        return (
          <li key={`${e.source}-${String(i)}`}>
            <strong>{key === undefined ? e.source : t(key)}</strong>: <Ltr>{e.detail}</Ltr>
          </li>
        );
      })}
    </ul>
  );
}

function EvidenceToggle({ evidence, open, onToggle }: { evidence: Evidence[]; open: boolean; onToggle: () => void }) {
  const { t } = useI18n();
  return (
    <button type="button" className="secondary" aria-expanded={open} onClick={onToggle}>
      {open ? t('disc.hideEvidence') : t('disc.showEvidence', { count: evidence.length })}
    </button>
  );
}

function ShowMore({ shown, total, onMore }: { shown: number; total: number; onMore: () => void }) {
  const { t } = useI18n();
  if (total <= shown) return null;
  return (
    <div className="row">
      <span className="muted small">{t('disc.shown', { shown, total })}</span>
      <button type="button" className="secondary" onClick={onMore}>
        {t('disc.showMore', { count: total - shown })}
      </button>
    </div>
  );
}

function useExpanded() {
  const [open, setOpen] = useState<ReadonlySet<number>>(new Set());
  return {
    has: (id: number) => open.has(id),
    toggle: (id: number) => {
      setOpen((prev) => {
        const next = new Set(prev);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        return next;
      });
    },
  };
}

export function roleOf(value: string): SegmentRole | undefined {
  return SEGMENT_ROLES.find((r) => r === value);
}

function DomainSelect({
  label,
  value,
  domains,
  onChange,
}: {
  label: string;
  value: string | null;
  domains: AssetDomain[];
  onChange: (domain: string | null) => void;
}) {
  const { t } = useI18n();
  const names = domains.map((d) => d.name);
  if (value !== null && !names.includes(value)) names.push(value);
  return (
    <select
      aria-label={label}
      value={value ?? ''}
      onChange={(e) => {
        onChange(e.target.value === '' ? null : e.target.value);
      }}
    >
      <option value="">{t('disc.noDomain')}</option>
      {names.map((n) => (
        <option key={n} value={n}>
          {n}
        </option>
      ))}
    </select>
  );
}

function StatusBadge({ confirmed }: { confirmed: boolean }) {
  const { t } = useI18n();
  return confirmed ? <span className="badge status-approved">{t('disc.approved')}</span> : <span className="badge status-pending">{t('disc.pending')}</span>;
}

/** Discovered asset groups that wait for approval. */
export function SuggestionsSection({
  groups,
  domains,
  writable,
  run,
  onOpen,
  onPurge,
}: {
  groups: AssetGroup[];
  domains: AssetDomain[];
  writable: boolean;
  run: Run;
  onOpen: (id: number) => void;
  onPurge: (request: PurgeRequest) => void;
}) {
  const { t } = useI18n();
  const [limit, setLimit] = useState(PAGE);
  const expanded = useExpanded();
  if (groups.length === 0) return null;

  const patch = (g: AssetGroup, body: Record<string, unknown>) =>
    run(async () => {
      await api(`/api/asset-groups/${String(g.id)}`, 'PATCH', body);
      return t('assets.saved');
    });

  return (
    <section className="card" aria-label={t('disc.suggestions')}>
      <div className="row spread">
        <div>
          <h2>
            {t('disc.suggestions')} ({groups.length})
          </h2>
          <p className="muted small">{t('disc.suggestionsHelp')}</p>
        </div>
        {writable && (
          <div className="row">
            <button
              type="button"
              onClick={() =>
                void run(async () => {
                  const r = await api<{ confirmed: number }>('/api/asset-groups/confirm', 'POST', { all: true });
                  return t('disc.confirmedCount', { count: r.confirmed });
                })
              }
            >
              {t('disc.approveAll')}
            </button>
            <button
              type="button"
              className="danger"
              onClick={() => {
                onPurge({ path: '/api/assets/purge', scope: 'suggested', text: 'disc.dialog.suggested' });
              }}
            >
              {t('disc.deleteSuggestions')}
            </button>
          </div>
        )}
      </div>
      <table>
        <SortedTable
          rows={groups}
          limit={limit}
          columns={{
            name: (g) => g.name,
            kind: (g) => g.kind,
            tier: (g) => TIERS.indexOf(g.tier),
            domain: (g) => g.domain ?? '',
            components: (g) => g.components.length,
            confidence: (g) => g.confidence,
          }}
          head={(th) => (
            <tr>
              {th('name', t('disc.col.name'))}
              {th('kind', t('disc.col.kind'))}
              {th('tier', t('disc.col.tier'))}
              {th('domain', t('disc.col.domain'))}
              {th('components', t('disc.col.components'), true)}
              {th('confidence', t('disc.col.confidence'), true)}
              <th>{t('disc.col.evidence')}</th>
              {writable && <th>{t('disc.col.actions')}</th>}
            </tr>
          )}
        >
          {(g) => (
            <Fragment key={g.id}>
              <tr className="inactive">
                <td>
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => {
                      onOpen(g.id);
                    }}
                  >
                    <bdi>{g.name}</bdi>
                  </button>
                </td>
                <td>{t(`assets.kind.${g.kind}`)}</td>
                <td className="edit-cell">
                  {writable ? (
                    <select
                      aria-label={`${t('disc.col.tier')} — ${g.name}`}
                      value={g.tier}
                      onChange={(e) => {
                        const tier: Tier | undefined = TIERS.find((x) => x === e.target.value);
                        if (tier !== undefined) void patch(g, { tier });
                      }}
                    >
                      {TIERS.map((tier) => (
                        <option key={tier} value={tier}>
                          {tier}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <span className={`tier tier-${g.tier.toLowerCase()}`}>{g.tier}</span>
                  )}
                </td>
                <td className="edit-cell">
                  {writable ? (
                    <DomainSelect
                      label={`${t('disc.col.domain')} — ${g.name}`}
                      value={g.domain}
                      domains={domains}
                      onChange={(domain) => void patch(g, { domain })}
                    />
                  ) : (
                    (g.domain ?? '')
                  )}
                </td>
                <td className="num">{g.components.length}</td>
                <td className="num">{g.confidence}%</td>
                <td>
                  <EvidenceToggle
                    evidence={g.evidence}
                    open={expanded.has(g.id)}
                    onToggle={() => {
                      expanded.toggle(g.id);
                    }}
                  />
                </td>
                {writable && (
                  <td className="actions">
                    <button
                      type="button"
                      aria-label={`${t('disc.approve')} — ${g.name}`}
                      onClick={() =>
                        void run(async () => {
                          await api('/api/asset-groups/confirm', 'POST', { ids: [g.id] });
                          return t('disc.done');
                        })
                      }
                    >
                      {t('disc.approve')}
                    </button>
                    <button
                      type="button"
                      className="danger"
                      aria-label={`${t('common.delete')} — ${g.name}`}
                      onClick={() =>
                        void run(async () => {
                          await api(`/api/asset-groups/${String(g.id)}`, 'DELETE');
                          return t('disc.done');
                        })
                      }
                    >
                      {t('common.delete')}
                    </button>
                  </td>
                )}
              </tr>
              {expanded.has(g.id) && (
                <tr className="evidence-row">
                  <td colSpan={writable ? 8 : 7}>
                    <EvidenceList evidence={g.evidence} />
                  </td>
                </tr>
              )}
            </Fragment>
          )}
        </SortedTable>
      </table>
      <ShowMore
        shown={Math.min(limit, groups.length)}
        total={groups.length}
        onMore={() => {
          setLimit(limit + PAGE);
        }}
      />
    </section>
  );
}

function RoleSelect({ label, value, onChange }: { label: string; value: SegmentRole; onChange: (role: SegmentRole) => void }) {
  const { t } = useI18n();
  return (
    <select
      aria-label={label}
      value={value}
      onChange={(e) => {
        const role = roleOf(e.target.value);
        if (role !== undefined) onChange(role);
      }}
    >
      {SEGMENT_ROLES.map((r) => (
        <option key={r} value={r}>
          {t(`disc.role.${r}`)}
        </option>
      ))}
    </select>
  );
}

/** A text input that saves on blur, only when the value changed. */
function BlurInput({ label, value, maxLength, onSave }: { label: string; value: string; maxLength: number; onSave: (value: string) => void }) {
  return (
    <input
      key={value}
      aria-label={label}
      dir="auto"
      maxLength={maxLength}
      defaultValue={value}
      onBlur={(e) => {
        const next = e.target.value.trim();
        if (next !== value) onSave(next);
      }}
    />
  );
}

export function SegmentsTab({
  segments,
  domains,
  writable,
  run,
  onPurge,
}: {
  segments: Segment[];
  domains: AssetDomain[];
  writable: boolean;
  run: Run;
  onPurge: (request: PurgeRequest) => void;
}) {
  const { t } = useI18n();
  const [role, setRole] = useState('');
  const [domain, setDomain] = useState('');
  const [search, setSearch] = useState('');
  const [pendingOnly, setPendingOnly] = useState(false);
  const [limit, setLimit] = useState(100);
  const expanded = useExpanded();
  const [form, setForm] = useState({ network: '', name: '', role: 'unknown' as SegmentRole, domain: '' });

  const needle = search.trim().toLowerCase();
  const shown = segments.filter(
    (s) =>
      (role === '' || s.role === role) &&
      (domain === '' || s.domain === domain) &&
      (!pendingOnly || !s.confirmed) &&
      (needle === '' ||
        s.network.toLowerCase().includes(needle) ||
        s.name.toLowerCase().includes(needle) ||
        s.cluster.toLowerCase().includes(needle) ||
        s.interface.toLowerCase().includes(needle) ||
        s.zone.toLowerCase().includes(needle)),
  );
  const pendingCount = segments.filter((s) => !s.confirmed).length;

  const patch = (s: Segment, body: Record<string, unknown>) =>
    run(async () => {
      await api(`/api/segments/${String(s.id)}`, 'PATCH', body);
      return t('assets.saved');
    });

  function add(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    void run(async () => {
      await api('/api/segments', 'POST', {
        network: form.network.trim(),
        role: form.role,
        ...(form.name.trim() !== '' ? { name: form.name.trim() } : {}),
        ...(form.domain !== '' ? { domain: form.domain } : {}),
      });
      setForm({ network: '', name: '', role: 'unknown', domain: '' });
      return t('assets.saved');
    });
  }

  return (
    <div className="stack">
      <p className="muted small">{t('disc.seg.help')}</p>
      <section className="card stack">
        <div className="row">
          <label>
            {t('disc.seg.filterRole')}
            <select
              value={role}
              onChange={(e) => {
                setRole(e.target.value);
                setLimit(100);
              }}
            >
              <option value="">{t('disc.seg.allRoles')}</option>
              {SEGMENT_ROLES.map((r) => (
                <option key={r} value={r}>
                  {t(`disc.role.${r}`)}
                </option>
              ))}
            </select>
          </label>
          <label>
            {t('disc.seg.filterDomain')}
            <select
              value={domain}
              onChange={(e) => {
                setDomain(e.target.value);
                setLimit(100);
              }}
            >
              <option value="">{t('disc.seg.allDomains')}</option>
              {domains.map((d) => (
                <option key={d.id} value={d.name}>
                  {d.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            {t('disc.seg.search')}
            <input
              type="search"
              dir="auto"
              maxLength={128}
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setLimit(100);
              }}
            />
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={pendingOnly}
              onChange={(e) => {
                setPendingOnly(e.target.checked);
                setLimit(100);
              }}
            />{' '}
            {t('disc.seg.pendingOnly')}
          </label>
        </div>
        {writable && (
          <div className="row">
            <button
              type="button"
              disabled={pendingCount === 0}
              onClick={() =>
                void run(async () => {
                  const r = await api<{ confirmed: number }>('/api/segments/confirm', 'POST', { all: true });
                  return t('disc.confirmedCount', { count: r.confirmed });
                })
              }
            >
              {t('disc.approveAll')}
            </button>
            <button
              type="button"
              className="danger"
              onClick={() => {
                onPurge({ path: '/api/segments/purge', scope: 'suggested', text: 'disc.dialog.segmentsSuggested' });
              }}
            >
              {t('disc.seg.deleteSuggested')}
            </button>
            <button
              type="button"
              className="danger"
              onClick={() => {
                onPurge({ path: '/api/segments/purge', scope: 'all', text: 'disc.dialog.segmentsAll' });
              }}
            >
              {t('disc.seg.deleteAll')}
            </button>
          </div>
        )}
      </section>

      {writable && (
        <form className="card row" onSubmit={add} aria-label={t('disc.seg.add')}>
          <label>
            {t('disc.seg.network')}
            <input dir="ltr" required maxLength={64} value={form.network} onChange={(e) => { setForm({ ...form, network: e.target.value }); }} />
          </label>
          <label>
            {t('disc.seg.name')}
            <input dir="auto" maxLength={128} value={form.name} onChange={(e) => { setForm({ ...form, name: e.target.value }); }} />
          </label>
          <label>
            {t('disc.seg.role')}
            <RoleSelect label={t('disc.seg.role')} value={form.role} onChange={(r) => { setForm({ ...form, role: r }); }} />
          </label>
          <label>
            {t('disc.seg.domain')}
            <DomainSelect label={t('disc.seg.domain')} value={form.domain === '' ? null : form.domain} domains={domains} onChange={(d) => { setForm({ ...form, domain: d ?? '' }); }} />
          </label>
          <button type="submit" disabled={form.network.trim() === ''}>
            <PlusIcon size={14} aria-hidden="true" /> {t('disc.seg.add')}
          </button>
        </form>
      )}

      {segments.length === 0 ? (
        <p className="muted">{t('disc.seg.none')}</p>
      ) : (
        <section className="card">
          <table>
            <SortedTable
              rows={shown}
              limit={limit}
              columns={{
                network: (s) => s.network,
                name: (s) => s.name,
                role: (s) => s.role,
                domain: (s) => s.domain ?? '',
                where: (s) => `${s.cluster} ${s.interface}`,
                source: (s) => s.source,
                confidence: (s) => s.confidence,
                status: (s) => s.confirmed,
              }}
              head={(th) => (
                <tr>
                  {th('network', t('disc.seg.network'))}
                  {th('name', t('disc.seg.name'))}
                  {th('role', t('disc.seg.role'))}
                  {th('domain', t('disc.seg.domain'))}
                  {th('where', t('disc.seg.where'))}
                  {th('source', t('disc.seg.source'))}
                  {th('confidence', t('disc.col.confidence'), true)}
                  {th('status', t('disc.col.status'))}
                  <th>{t('disc.col.evidence')}</th>
                  {writable && <th>{t('disc.col.actions')}</th>}
                </tr>
              )}
            >
              {(s) => (
                <Fragment key={s.id}>
                  <tr className={s.confirmed ? '' : 'inactive'}>
                    <td>
                      <Ltr>{s.network}</Ltr>
                    </td>
                    <td className="edit-cell">
                      {writable ? (
                        <BlurInput label={`${t('disc.seg.name')} — ${s.network}`} value={s.name} maxLength={128} onSave={(name) => void patch(s, { name })} />
                      ) : (
                        <bdi>{s.name}</bdi>
                      )}
                      {writable ? (
                        <BlurInput label={`${t('disc.seg.notes')} — ${s.network}`} value={s.notes} maxLength={512} onSave={(notes) => void patch(s, { notes })} />
                      ) : (
                        s.notes !== '' && <div className="muted small"><bdi>{s.notes}</bdi></div>
                      )}
                    </td>
                    <td className="edit-cell">
                      {writable ? (
                        <RoleSelect label={`${t('disc.seg.role')} — ${s.network}`} value={s.role} onChange={(r) => void patch(s, { role: r })} />
                      ) : (
                        t(`disc.role.${s.role}`)
                      )}
                    </td>
                    <td className="edit-cell">
                      {writable ? (
                        <DomainSelect label={`${t('disc.seg.domain')} — ${s.network}`} value={s.domain} domains={domains} onChange={(d) => void patch(s, { domain: d })} />
                      ) : (
                        (s.domain ?? '')
                      )}
                    </td>
                    <td>
                      <Ltr>{[s.cluster, s.interface, s.zone].filter((x) => x !== '').join(' / ')}</Ltr>
                      {s.gateway && <div><span className="badge">{t('disc.seg.gateway')}</span></div>}
                      {s.in_dc && <div><span className="badge">{t('disc.seg.inDc')}</span></div>}
                    </td>
                    <td>{t(s.source === 'manual' ? 'disc.seg.source.manual' : 'disc.seg.source.discovery')}</td>
                    <td className="num">{s.confidence}%</td>
                    <td>
                      <StatusBadge confirmed={s.confirmed} />
                    </td>
                    <td>
                      <EvidenceToggle
                        evidence={s.evidence}
                        open={expanded.has(s.id)}
                        onToggle={() => {
                          expanded.toggle(s.id);
                        }}
                      />
                    </td>
                    {writable && (
                      <td className="actions">
                        {!s.confirmed && (
                          <button type="button" aria-label={`${t('disc.approve')} — ${s.network}`} onClick={() => void patch(s, { confirmed: true })}>
                            {t('disc.approve')}
                          </button>
                        )}
                        <button
                          type="button"
                          className="danger"
                          aria-label={`${t('common.delete')} — ${s.network}`}
                          onClick={() =>
                            void run(async () => {
                              await api(`/api/segments/${String(s.id)}`, 'DELETE');
                              return t('disc.done');
                            })
                          }
                        >
                          {t('common.delete')}
                        </button>
                      </td>
                    )}
                  </tr>
                  {expanded.has(s.id) && (
                    <tr className="evidence-row">
                      <td colSpan={writable ? 10 : 9}>
                        <EvidenceList evidence={s.evidence} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              )}
            </SortedTable>
          </table>
          <ShowMore
            shown={Math.min(limit, shown.length)}
            total={shown.length}
            onMore={() => {
              setLimit(limit + 100);
            }}
          />
        </section>
      )}
    </div>
  );
}

export function DomainsTab({ domains, writable, run }: { domains: AssetDomain[]; writable: boolean; run: Run }) {
  const { t } = useI18n();
  const expanded = useExpanded();
  const [form, setForm] = useState({ name: '', description: '' });

  const patch = (d: AssetDomain, body: Record<string, unknown>) =>
    run(async () => {
      await api(`/api/asset-domains/${String(d.id)}`, 'PATCH', body);
      return t('assets.saved');
    });

  function add(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    void run(async () => {
      await api('/api/asset-domains', 'POST', {
        name: form.name.trim(),
        ...(form.description.trim() !== '' ? { description: form.description.trim() } : {}),
      });
      setForm({ name: '', description: '' });
      return t('assets.saved');
    });
  }

  return (
    <div className="stack">
      <p className="muted small">{t('disc.dom.help')}</p>
      {writable && (
        <form className="card row" onSubmit={add} aria-label={t('disc.dom.add')}>
          <label>
            {t('disc.dom.name')}
            <input dir="ltr" required maxLength={64} value={form.name} onChange={(e) => { setForm({ ...form, name: e.target.value }); }} />
          </label>
          <label>
            {t('disc.dom.description')}
            <input dir="auto" maxLength={512} value={form.description} onChange={(e) => { setForm({ ...form, description: e.target.value }); }} />
          </label>
          <button type="submit" disabled={form.name.trim() === ''}>
            <PlusIcon size={14} aria-hidden="true" /> {t('disc.dom.add')}
          </button>
        </form>
      )}
      {domains.length === 0 ? (
        <p className="muted">{t('disc.dom.none')}</p>
      ) : (
        <section className="card">
          <table>
            <SortedTable
              rows={domains}
              columns={{
                name: (d) => d.name,
                description: (d) => d.description,
                source: (d) => d.source,
                status: (d) => d.confirmed,
                segments: (d) => d.segments,
                assets: (d) => d.assets,
              }}
              head={(th) => (
                <tr>
                  {th('name', t('disc.dom.name'))}
                  {th('description', t('disc.dom.description'))}
                  {th('source', t('disc.seg.source'))}
                  {th('status', t('disc.col.status'))}
                  {th('segments', t('disc.dom.segments'), true)}
                  {th('assets', t('disc.dom.assets'), true)}
                  <th>{t('disc.col.evidence')}</th>
                  {writable && <th>{t('disc.col.actions')}</th>}
                </tr>
              )}
            >
              {(d) => (
                <Fragment key={d.id}>
                  <tr className={d.confirmed ? '' : 'inactive'}>
                    <td className="edit-cell">
                      {writable ? (
                        <input
                          key={d.name}
                          aria-label={`${t('disc.dom.name')} — ${d.name}`}
                          dir="ltr"
                          maxLength={64}
                          defaultValue={d.name}
                          onBlur={(e) => {
                            const next = e.target.value.trim();
                            if (next !== '' && next !== d.name) void patch(d, { name: next });
                          }}
                        />
                      ) : (
                        <Ltr>{d.name}</Ltr>
                      )}
                    </td>
                    <td className="edit-cell">
                      {writable ? (
                        <BlurInput label={`${t('disc.dom.description')} — ${d.name}`} value={d.description} maxLength={512} onSave={(description) => void patch(d, { description })} />
                      ) : (
                        <bdi>{d.description}</bdi>
                      )}
                    </td>
                    <td>{t(d.source === 'manual' ? 'disc.seg.source.manual' : 'disc.seg.source.discovery')}</td>
                    <td>
                      <StatusBadge confirmed={d.confirmed} />
                    </td>
                    <td className="num">{d.segments}</td>
                    <td className="num">{d.assets}</td>
                    <td>
                      <EvidenceToggle
                        evidence={d.evidence}
                        open={expanded.has(d.id)}
                        onToggle={() => {
                          expanded.toggle(d.id);
                        }}
                      />
                    </td>
                    {writable && (
                      <td className="actions">
                        {!d.confirmed && (
                          <button type="button" aria-label={`${t('disc.approve')} — ${d.name}`} onClick={() => void patch(d, { confirmed: true })}>
                            {t('disc.approve')}
                          </button>
                        )}
                        <button
                          type="button"
                          className="danger"
                          aria-label={`${t('common.delete')} — ${d.name}`}
                          onClick={() => {
                            if (!window.confirm(t('disc.dom.deleteConfirm', { name: d.name }))) return;
                            void run(async () => {
                              await api(`/api/asset-domains/${String(d.id)}`, 'DELETE');
                              return t('disc.done');
                            });
                          }}
                        >
                          {t('common.delete')}
                        </button>
                      </td>
                    )}
                  </tr>
                  {expanded.has(d.id) && (
                    <tr className="evidence-row">
                      <td colSpan={writable ? 8 : 7}>
                        <EvidenceList evidence={d.evidence} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              )}
            </SortedTable>
          </table>
        </section>
      )}
    </div>
  );
}
