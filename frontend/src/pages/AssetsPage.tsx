import { HardDriveIcon, PlusIcon, TreeStructureIcon, UserIcon, UsersThreeIcon } from '@phosphor-icons/react';
import { useState } from 'react';
import type { ChangeEvent, SyntheticEvent } from 'react';
import { SortedTable } from '../components/sort';

import { ApiError, api, errorCode } from '../api/client';
import { ASSET_KINDS, TIERS } from '../api/types';
import type { Asset, AssetGroup, AssetKind, Tier } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { Alert, Ltr } from '../components/common';
import { useApi, useQueryParam, useSnapshotSelection } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';

type Message = { kind: 'error' | 'success'; text: string } | null;

const MAX_FILE_BYTES = 1_000_000;
const EMPTY_GROUP = { name: '', kind: 'system' as AssetKind, tier: 'GOLD' as Tier, user_type: '', owner: '', description: '' };
const EMPTY_COMPONENT = { name: '', network: '', role: '', ports: '', notes: '' };

function errorLines(body: unknown): string {
  if (typeof body !== 'object' || body === null || !('errors' in body) || !Array.isArray(body.errors)) return '?';
  return body.errors
    .map((e: unknown) => (typeof e === 'object' && e !== null && 'line' in e ? String(e.line) : '?'))
    .join(', ');
}

function KindIcon({ kind }: { kind: AssetKind }) {
  switch (kind) {
    case 'server':
      return <HardDriveIcon size={18} aria-hidden="true" />;
    case 'user':
      return <UserIcon size={18} aria-hidden="true" />;
    case 'user_segment':
      return <UsersThreeIcon size={18} aria-hidden="true" />;
    default:
      return <TreeStructureIcon size={18} aria-hidden="true" />;
  }
}

/**
 * Assets: systems, servers, users and user segments, each with its components (address,
 * ports, role). The asset's classification drives every analysis; components inherit it.
 */
export function AssetsPage() {
  const { t, tError } = useI18n();
  const { can } = useAuth();
  const writable = can('assets:write');
  const groups = useApi<AssetGroup[]>('/api/asset-groups');
  const entries = useApi<Asset[]>('/api/assets');
  const { snapshotId } = useSnapshotSelection();
  const [selectedParam, setSelected] = useQueryParam('asset');
  const [creating, setCreating] = useState(false);
  const [filter, setFilter] = useState('');
  const [tierFilter, setTierFilter] = useState<Tier | null>(null);
  const [message, setMessage] = useState<Message>(null);

  const unassigned = (entries.data ?? []).filter((a) => a.group_id === null);
  const pending = unassigned.filter((a) => !a.confirmed);
  const shown = (groups.data ?? []).filter(
    (g) =>
      (tierFilter === null || g.tier === tierFilter) &&
      (filter.trim() === '' ||
        g.name.toLowerCase().includes(filter.trim().toLowerCase()) ||
        g.components.some((c) => c.network.includes(filter.trim()) || c.system.toLowerCase().includes(filter.trim().toLowerCase()))),
  );
  const selected = (groups.data ?? []).find((g) => String(g.id) === selectedParam) ?? null;

  function reload() {
    groups.reload();
    entries.reload();
  }

  async function run(action: () => Promise<string>) {
    try {
      setMessage({ kind: 'success', text: await action() });
      reload();
    } catch (err: unknown) {
      setMessage({ kind: 'error', text: tError(errorCode(err)) });
    }
  }

  async function importFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (file === undefined) return;
    if (file.size > MAX_FILE_BYTES) {
      setMessage({ kind: 'error', text: tError('request_too_large') });
      return;
    }
    const text = await file.text();
    try {
      const result = await api<{ created: number; updated: number }>('/api/assets/import', 'POST', { csv: text });
      setMessage({ kind: 'success', text: t('assets.importDone', result) });
      reload();
    } catch (err: unknown) {
      if (err instanceof ApiError && err.code === 'csv_invalid_rows') {
        setMessage({ kind: 'error', text: t('assets.importErrors', { lines: errorLines(err.body) }) });
      } else {
        setMessage({ kind: 'error', text: tError(errorCode(err)) });
      }
    }
  }

  async function exportCsv() {
    const response = await fetch('/api/assets/export', { credentials: 'same-origin', cache: 'no-store' });
    if (!response.ok) return;
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement('a');
    link.href = url;
    link.download = 'assets.csv';
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="stack">
      <div className="row spread">
        <div>
          <h1>{t('assets.title')}</h1>
          <p className="muted small">{t('assets.help')}</p>
        </div>
        <div className="row">
          <button type="button" className="secondary" onClick={() => void exportCsv()}>
            {t('assets.export')}
          </button>
          {writable && (
            <>
              <label className="button secondary">
                {t('assets.import')}
                <input type="file" accept=".csv,text/csv" className="visually-hidden" onChange={(e) => void importFile(e)} />
              </label>
              {snapshotId !== null && (
                <button
                  type="button"
                  className="secondary"
                  onClick={() =>
                    void run(async () => {
                      const r = await api<{ created: number }>('/api/assets/bootstrap', 'POST', { snapshot_id: snapshotId });
                      return t('assets.bootstrapDone', { count: r.created });
                    })
                  }
                >
                  {t('assets.bootstrap')}
                </button>
              )}
              <button
                type="button"
                onClick={() => {
                  setCreating(true);
                  setSelected(null);
                }}
              >
                <PlusIcon size={14} aria-hidden="true" /> {t('assets.new')}
              </button>
            </>
          )}
        </div>
      </div>
      {groups.error !== null && <Alert kind="error">{tError(groups.error)}</Alert>}
      {message !== null && <Alert kind={message.kind}>{message.text}</Alert>}

      <div className="asset-layout">
        <section className="card asset-list" aria-label={t('assets.title')}>
          <input
            type="search"
            dir="auto"
            maxLength={128}
            placeholder={t('assets.filter')}
            aria-label={t('assets.filter')}
            value={filter}
            onChange={(e) => {
              setFilter(e.target.value);
            }}
          />
          <div className="tier-filter" role="group" aria-label={t('assets.tier')}>
            {[null, ...TIERS].map((tier) => (
              <button
                key={tier ?? 'all'}
                type="button"
                aria-pressed={tierFilter === tier}
                className={tierFilter === tier ? 'active' : ''}
                onClick={() => {
                  setTierFilter(tier);
                }}
              >
                {tier ?? t('assets.allTiers')}
              </button>
            ))}
          </div>
          {groups.data !== null && groups.data.length === 0 && <p className="muted small">{t('assets.none')}</p>}
          <ul className="asset-items">
            {shown.map((g) => (
              <li key={g.id}>
                <button
                  type="button"
                  className={`asset-item${selected?.id === g.id ? ' active' : ''}`}
                  aria-pressed={selected?.id === g.id}
                  onClick={() => {
                    setSelected(String(g.id));
                    setCreating(false);
                  }}
                >
                  <KindIcon kind={g.kind} />
                  <span className="asset-item-text">
                    <strong>
                      <bdi>{g.name}</bdi>
                    </strong>
                    <span className="muted small">
                      {t(`assets.kind.${g.kind}`)} · {t('assets.componentsCount', { count: g.components.length })}
                    </span>
                  </span>
                  <span className={`tier tier-${g.tier.toLowerCase()}`}>{g.tier}</span>
                </button>
              </li>
            ))}
          </ul>
        </section>

        <section className="card asset-detail" aria-live="polite">
          {creating && writable ? (
            <GroupForm
              onCancel={() => {
                setCreating(false);
              }}
              onSaved={(g) => {
                setCreating(false);
                setSelected(String(g.id));
                setMessage({ kind: 'success', text: t('assets.saved') });
                reload();
              }}
            />
          ) : selected !== null ? (
            <GroupDetail
              key={selected.id}
              group={selected}
              groups={groups.data ?? []}
              writable={writable}
              run={run}
              onDeleted={() => {
                setSelected(null);
              }}
            />
          ) : (
            <p className="muted">{t('assets.select')}</p>
          )}
        </section>
      </div>

      {unassigned.length > 0 && (
        <section className="card">
          <div className="row spread">
            <div>
              <h2>{t('assets.unassigned')}</h2>
              <p className="muted small">{t('assets.unassignedHelp')}</p>
            </div>
            {writable && pending.length > 0 && (
              <button
                type="button"
                onClick={() =>
                  void run(async () => {
                    await api('/api/assets/confirm', 'POST', { ids: pending.map((a) => a.id) });
                    return t('assets.saved');
                  })
                }
              >
                {t('assets.confirmAll', { count: pending.length })}
              </button>
            )}
          </div>
          <table>
            <SortedTable
              rows={unassigned}
              columns={{ network: (a) => a.network, system: (a) => a.system, tier: (a) => TIERS.indexOf(a.tier), source: (a) => a.source }}
              head={(th) => (
                <tr>
                  {th('network', t('assets.network'))}
                  {th('system', t('assets.system'))}
                  {th('tier', t('assets.tier'))}
                  {th('source', t('assets.source'))}
                  {writable && <th>{t('common.actions')}</th>}
                </tr>
              )}
            >
              {(a) => (
                <tr key={a.id} className={a.confirmed ? '' : 'inactive'}>
                  <td>
                    <Ltr>{a.network}</Ltr>
                  </td>
                  <td>
                    <bdi>{a.system}</bdi>
                  </td>
                  <td>
                    <span className={`tier tier-${a.tier.toLowerCase()}`}>{a.tier}</span>
                  </td>
                  <td>
                    {a.source}
                    {!a.confirmed && <div className="muted small">{t('assets.pending')}</div>}
                  </td>
                  {writable && (
                    <td className="actions">
                      {!a.confirmed && (
                        <button
                          type="button"
                          className="secondary"
                          onClick={() =>
                            void run(async () => {
                              await api('/api/assets/confirm', 'POST', { ids: [a.id] });
                              return t('assets.saved');
                            })
                          }
                        >
                          {t('assets.confirm')}
                        </button>
                      )}
                      {(groups.data ?? []).length > 0 && (
                        <select
                          aria-label={`${t('assets.moveTo')} — ${a.network}`}
                          value=""
                          onChange={(e) => {
                            const target = e.target.value;
                            void run(async () => {
                              await api(`/api/assets/${String(a.id)}`, 'PATCH', { group_id: Number(target) });
                              return t('assets.saved');
                            });
                          }}
                        >
                          <option value="">{t('assets.moveTo')}…</option>
                          {(groups.data ?? []).map((g) => (
                            <option key={g.id} value={g.id}>
                              {g.name}
                            </option>
                          ))}
                        </select>
                      )}
                      <button
                        type="button"
                        className="danger"
                        onClick={() =>
                          void run(async () => {
                            await api(`/api/assets/${String(a.id)}`, 'DELETE');
                            return t('assets.saved');
                          })
                        }
                      >
                        {t('common.delete')}
                      </button>
                    </td>
                  )}
                </tr>
              )}
            </SortedTable>
          </table>
        </section>
      )}
      {writable && <p className="muted small">{t('assets.csvHelp')}</p>}
    </div>
  );
}

function GroupForm({
  group,
  onCancel,
  onSaved,
}: {
  group?: AssetGroup;
  onCancel: () => void;
  onSaved: (g: AssetGroup) => void;
}) {
  const { t, tError } = useI18n();
  const [form, setForm] = useState(
    group === undefined
      ? EMPTY_GROUP
      : { name: group.name, kind: group.kind, tier: group.tier, user_type: group.user_type ?? '', owner: group.owner, description: group.description },
  );
  const [error, setError] = useState<string | null>(null);
  const forUsers = form.kind === 'user' || form.kind === 'user_segment';

  async function submit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    const body = {
      name: form.name.trim(),
      kind: form.kind,
      tier: form.tier,
      owner: form.owner.trim(),
      description: form.description.trim(),
      ...(forUsers && form.user_type.trim() !== '' ? { user_type: form.user_type.trim() } : {}),
    };
    try {
      const saved =
        group === undefined
          ? await api<AssetGroup>('/api/asset-groups', 'POST', body)
          : await api<AssetGroup>(`/api/asset-groups/${String(group.id)}`, 'PATCH', body);
      onSaved(saved);
    } catch (err: unknown) {
      setError(errorCode(err));
    }
  }

  return (
    <form className="stack" onSubmit={(e) => void submit(e)}>
      <h2>{group === undefined ? t('assets.new') : t('assets.edit')}</h2>
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      <div className="grid">
        <label>
          {t('assets.name')}
          <input dir="auto" required maxLength={128} value={form.name} onChange={(e) => { setForm({ ...form, name: e.target.value }); }} />
        </label>
        <label>
          {t('assets.kind')}
          <select
            value={form.kind}
            onChange={(e) => {
              const kind = ASSET_KINDS.find((k) => k === e.target.value);
              if (kind !== undefined) setForm({ ...form, kind, tier: kind === 'user' || kind === 'user_segment' ? 'USERS' : form.tier });
            }}
          >
            {ASSET_KINDS.map((k) => (
              <option key={k} value={k}>
                {t(`assets.kind.${k}`)}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t('assets.tier')}
          <select
            value={form.tier}
            onChange={(e) => {
              const tier = TIERS.find((x) => x === e.target.value);
              if (tier !== undefined) setForm({ ...form, tier });
            }}
          >
            {TIERS.map((tier) => (
              <option key={tier} value={tier}>
                {tier}
              </option>
            ))}
          </select>
        </label>
        {forUsers && (
          <label>
            {t('assets.userType')}
            <input dir="ltr" maxLength={16} pattern="[A-Za-z0-9_-]+" value={form.user_type} onChange={(e) => { setForm({ ...form, user_type: e.target.value }); }} />
          </label>
        )}
        <label>
          {t('assets.owner')}
          <input dir="auto" maxLength={128} value={form.owner} onChange={(e) => { setForm({ ...form, owner: e.target.value }); }} />
        </label>
      </div>
      <label>
        {t('assets.description')}
        <input dir="auto" maxLength={512} value={form.description} onChange={(e) => { setForm({ ...form, description: e.target.value }); }} />
      </label>
      <div className="row">
        <button type="submit" disabled={form.name.trim() === ''}>
          {t('common.save')}
        </button>
        <button type="button" className="secondary" onClick={onCancel}>
          {t('common.cancel')}
        </button>
      </div>
    </form>
  );
}

function GroupDetail({
  group,
  groups,
  writable,
  run,
  onDeleted,
}: {
  group: AssetGroup;
  groups: AssetGroup[];
  writable: boolean;
  run: (action: () => Promise<string>) => Promise<void>;
  onDeleted: () => void;
}) {
  const { t } = useI18n();
  const [editing, setEditing] = useState(false);
  const [component, setComponent] = useState(EMPTY_COMPONENT);

  if (editing) {
    return (
      <GroupForm
        group={group}
        onCancel={() => {
          setEditing(false);
        }}
        onSaved={() => {
          setEditing(false);
          void run(() => Promise.resolve(t('assets.saved')));
        }}
      />
    );
  }

  async function addComponent(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    await run(async () => {
      await api(`/api/asset-groups/${String(group.id)}/components`, 'POST', {
        name: component.name.trim(),
        network: component.network.trim(),
        role: component.role.trim(),
        ports: component.ports.trim(),
        notes: component.notes.trim(),
      });
      setComponent(EMPTY_COMPONENT);
      return t('assets.saved');
    });
  }

  return (
    <div className="stack">
      <div className="row spread">
        <div className="asset-title">
          <KindIcon kind={group.kind} />
          <h2>
            <bdi>{group.name}</bdi>
          </h2>
          <span className={`tier tier-${group.tier.toLowerCase()}`}>{group.tier}</span>
          <span className="muted small">{t(`assets.kind.${group.kind}`)}</span>
          {group.user_type !== null && <span className="badge">{group.user_type}</span>}
        </div>
        {writable && (
          <div className="row">
            <button
              type="button"
              className="secondary"
              onClick={() => {
                setEditing(true);
              }}
            >
              {t('assets.edit')}
            </button>
            <button
              type="button"
              className="danger"
              onClick={() => {
                if (!window.confirm(t('assets.deleteConfirm', { name: group.name, count: group.components.length }))) return;
                void run(async () => {
                  await api(`/api/asset-groups/${String(group.id)}`, 'DELETE');
                  onDeleted();
                  return t('assets.saved');
                });
              }}
            >
              {t('assets.delete')}
            </button>
          </div>
        )}
      </div>
      {(group.owner !== '' || group.description !== '') && (
        <p className="muted small">
          {group.owner !== '' && (
            <>
              {t('assets.owner')}: <bdi>{group.owner}</bdi>
              {group.description !== '' && ' · '}
            </>
          )}
          <bdi>{group.description}</bdi>
        </p>
      )}

      <h3>{t('assets.components')}</h3>
      {group.components.length === 0 ? (
        <p className="muted small">{t('assets.noComponents')}</p>
      ) : (
        <table>
          <SortedTable
            rows={group.components}
            columns={{ name: (c) => c.system, network: (c) => c.network, role: (c) => c.system_type, ports: (c) => c.ports, notes: (c) => c.notes }}
            head={(th) => (
              <tr>
                {th('name', t('assets.componentName'))}
                {th('network', t('assets.network'))}
                {th('role', t('assets.role'))}
                {th('ports', t('assets.ports'))}
                {th('notes', t('assets.notes'))}
                {writable && <th>{t('common.actions')}</th>}
              </tr>
            )}
          >
            {(c) => (
              <tr key={c.id}>
                <td>
                  <bdi>{c.system}</bdi>
                </td>
                <td>
                  <Ltr>{c.network}</Ltr>
                </td>
                <td>{c.system_type}</td>
                <td>
                  <Ltr>{c.ports}</Ltr>
                </td>
                <td className="small">
                  <bdi>{c.notes}</bdi>
                </td>
                {writable && (
                  <td className="actions">
                    <select
                      aria-label={`${t('assets.moveTo')} — ${c.network}`}
                      value=""
                      onChange={(e) => {
                        const target = e.target.value;
                        void run(async () => {
                          await api(`/api/assets/${String(c.id)}`, 'PATCH', { group_id: target === 'none' ? null : Number(target) });
                          return t('assets.saved');
                        });
                      }}
                    >
                      <option value="">{t('assets.moveTo')}…</option>
                      {groups
                        .filter((g) => g.id !== group.id)
                        .map((g) => (
                          <option key={g.id} value={g.id}>
                            {g.name}
                          </option>
                        ))}
                      <option value="none">{t('assets.removeFromAsset')}</option>
                    </select>
                    <button
                      type="button"
                      className="danger"
                      onClick={() =>
                        void run(async () => {
                          await api(`/api/assets/${String(c.id)}`, 'DELETE');
                          return t('assets.saved');
                        })
                      }
                    >
                      {t('common.delete')}
                    </button>
                  </td>
                )}
              </tr>
            )}
          </SortedTable>
        </table>
      )}

      {writable && (
        <form className="component-form" onSubmit={(e) => void addComponent(e)}>
          <input aria-label={t('assets.componentName')} placeholder={t('assets.componentName')} dir="auto" maxLength={128} value={component.name} onChange={(e) => { setComponent({ ...component, name: e.target.value }); }} />
          <input aria-label={t('assets.network')} placeholder={t('assets.network')} dir="ltr" maxLength={96} value={component.network} onChange={(e) => { setComponent({ ...component, network: e.target.value }); }} />
          <input aria-label={t('assets.role')} placeholder={t('assets.role')} dir="auto" maxLength={32} value={component.role} onChange={(e) => { setComponent({ ...component, role: e.target.value }); }} />
          <input aria-label={t('assets.ports')} placeholder="TCP 1433, UDP 53" dir="ltr" maxLength={256} value={component.ports} onChange={(e) => { setComponent({ ...component, ports: e.target.value }); }} />
          <button type="submit" disabled={component.name.trim() === '' || component.network.trim() === ''}>
            <PlusIcon size={14} aria-hidden="true" /> {t('assets.addComponent')}
          </button>
        </form>
      )}
    </div>
  );
}
