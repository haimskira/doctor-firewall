import { useMemo, useState } from 'react';
import type { SyntheticEvent } from 'react';

import { api, errorCode } from '../api/client';
import { RECOMMENDATION_KINDS } from '../api/types';
import { CHANGING_KINDS, FINDING_KINDS } from '../components/catalog';
import { Alert, DateTime, Ltr } from '../components/common';
import { phaseOf } from '../components/roadmap';
import { useApi } from '../hooks';
import { isMessageKey, useI18n } from '../i18n/I18nProvider';

interface Token {
  id: number;
  name: string;
  prefix: string;
  owner: string;
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

interface Param {
  name: string;
  in: 'path' | 'query' | 'header' | 'cookie';
  required?: boolean;
  description?: string;
  schema?: { type?: string; enum?: string[]; default?: unknown; anyOf?: { type?: string; enum?: string[] }[] };
}

interface Operation {
  summary?: string;
  description?: string;
  tags?: string[];
  parameters?: Param[];
}

interface OpenApi {
  info: { title: string; version: string; description?: string };
  paths: Record<string, { get?: Operation }>;
}

interface Endpoint {
  path: string;
  tag: string;
  op: Operation;
}

const TABS = ['overview', 'tokens', 'explorer', 'reference'] as const;
type Tab = (typeof TABS)[number];
const MAX_SHOWN = 200_000; // characters of a response shown in the explorer

/** The API for developers and other systems: tokens, quick start, explorer and reference. */
export function ApiDocsPage() {
  const { t } = useI18n();
  const [tab, setTab] = useState<Tab>('overview');
  return (
    <div className="stack">
      <h1>{t('apidocs.title')}</h1>
      <p className="muted">{t('apidocs.help')}</p>
      <div className="row" role="tablist" aria-label={t('apidocs.title')}>
        {TABS.map((name) => (
          <button
            key={name}
            type="button"
            role="tab"
            aria-selected={tab === name}
            className={tab === name ? '' : 'secondary'}
            onClick={() => {
              setTab(name);
            }}
          >
            {t(`apidocs.tab.${name}`)}
          </button>
        ))}
      </div>
      {tab === 'overview' && <Overview />}
      {tab === 'tokens' && <Tokens />}
      {tab === 'explorer' && <Explorer />}
      {tab === 'reference' && <Reference />}
    </div>
  );
}

function Overview() {
  const { t } = useI18n();
  const base = `${window.location.origin}/api`;
  return (
    <section className="card stack">
      <h2>{t('apidocs.overview.title')}</h2>
      <ul className="plain-list apidocs-points">
        {(['base', 'auth', 'readonly', 'format', 'paging', 'perms'] as const).map((k) => (
          <li key={k}>{t(`apidocs.overview.${k}`, { base })}</li>
        ))}
      </ul>
      <h3>{t('apidocs.quick.title')}</h3>
      <pre className="apidocs-code" dir="ltr">
        {[
          `export DF_TOKEN=dfk_...   # API → ${t('apidocs.tab.tokens')}`,
          `curl -s -H "Authorization: Bearer $DF_TOKEN" ${base}/snapshots?limit=5`,
          `curl -s -H "Authorization: Bearer $DF_TOKEN" "${base}/snapshots/<id>/findings?severity=high&limit=500"`,
          `curl -s -H "Authorization: Bearer $DF_TOKEN" "${base}/snapshots/<id>/recommendations?phase=objects&limit=500"`,
          `curl -s -H "Authorization: Bearer $DF_TOKEN" ${base}/snapshots/<id>/roadmap`,
          `curl -s -H "Authorization: Bearer $DF_TOKEN" ${base}/history`,
          `curl -s -H "Authorization: Bearer $DF_TOKEN" ${base}/openapi.json   # ${t('apidocs.quick.schema')}`,
        ].join('\n')}
      </pre>
      <h3>{t('apidocs.capabilities.title')}</h3>
      <ul className="apidocs-capabilities">
        {CAPABILITIES.map((c) => (
          <li key={c.key}>
            <strong>{t(`apidocs.cap.${c.key}`)}</strong> — {t(`apidocs.cap.${c.key}.text`)}{' '}
            <span className="muted small">
              {c.paths.map((p) => (
                <code key={p} className="ltr">
                  {p}
                </code>
              ))}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

const CAPABILITIES = [
  { key: 'inventory', paths: ['/api/snapshots', '/api/snapshots/{id}/policies', '/api/snapshots/{id}/policies/{policy}/rules', '/api/snapshots/{id}/objects'] },
  { key: 'findings', paths: ['/api/snapshots/{id}/findings'] },
  { key: 'scores', paths: ['/api/snapshots/{id}/scores', '/api/snapshots/{id}/dashboard'] },
  { key: 'recommendations', paths: ['/api/snapshots/{id}/recommendations', '/api/snapshots/{id}/recommendations/{rec_id}'] },
  { key: 'roadmap', paths: ['/api/snapshots/{id}/roadmap'] },
  { key: 'map', paths: ['/api/snapshots/{id}/map'] },
  { key: 'attack', paths: ['/api/snapshots/{id}/attack-surface', '/api/snapshots/{id}/attack-surface/targets'] },
  { key: 'network', paths: ['/api/snapshots/{id}/clusters', '/api/snapshots/{id}/clusters/{cluster}/network'] },
  { key: 'changesets', paths: ['/api/changesets', '/api/changesets/{id}'] },
  { key: 'history', paths: ['/api/history', '/api/changesets/{id}/batches/{seq}/changes'] },
  { key: 'jobs', paths: ['/api/jobs'] },
  { key: 'audit', paths: ['/api/audit'] },
] as const;

function Tokens() {
  const { t, tError } = useI18n();
  const list = useApi<Token[]>('/api/tokens');
  const [name, setName] = useState('');
  const [days, setDays] = useState('90');
  const [created, setCreated] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function create(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const out = await api<Token & { token: string }>('/api/tokens', 'POST', { name: name.trim(), days: Number(days) });
      setCreated(out.token);
      setName('');
      list.reload();
    } catch (err) {
      setError(errorCode(err));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(token: Token) {
    if (!window.confirm(t('apidocs.tokens.revokeConfirm', { name: token.name }))) return;
    try {
      await api(`/api/tokens/${String(token.id)}`, 'DELETE');
      list.reload();
    } catch (err) {
      setError(errorCode(err));
    }
  }

  return (
    <section className="card stack">
      <h2>{t('apidocs.tokens.title')}</h2>
      <p className="muted small">{t('apidocs.tokens.help')}</p>
      {(error ?? list.error) !== null && <Alert kind="error">{tError(error ?? list.error ?? '')}</Alert>}
      {created !== null && (
        <Alert kind="warning">
          <strong>{t('apidocs.tokens.once')}</strong>
          <pre className="apidocs-code" dir="ltr">
            {created}
          </pre>
          <button
            type="button"
            className="secondary"
            onClick={() => {
              void navigator.clipboard.writeText(created);
            }}
          >
            {t('apidocs.tokens.copy')}
          </button>
        </Alert>
      )}
      <form className="row" onSubmit={(e) => void create(e)}>
        <label className="inline-field">
          {t('apidocs.tokens.name')}
          <input
            value={name}
            maxLength={64}
            onChange={(e) => {
              setName(e.target.value);
            }}
          />
        </label>
        <label className="inline-field">
          {t('apidocs.tokens.days')}
          <select
            value={days}
            onChange={(e) => {
              setDays(e.target.value);
            }}
          >
            {['30', '90', '180', '365'].map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
        </label>
        <button type="submit" disabled={busy || name.trim().length < 3}>
          {t('apidocs.tokens.create')}
        </button>
      </form>
      {list.data !== null && list.data.length === 0 && <p className="muted">{t('apidocs.tokens.none')}</p>}
      {list.data !== null && list.data.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>{t('apidocs.tokens.name')}</th>
              <th>{t('apidocs.tokens.prefix')}</th>
              <th>{t('apidocs.tokens.owner')}</th>
              <th>{t('apidocs.tokens.created')}</th>
              <th>{t('apidocs.tokens.expires')}</th>
              <th>{t('apidocs.tokens.lastUsed')}</th>
              <th>{t('common.actions')}</th>
            </tr>
          </thead>
          <tbody>
            {list.data.map((tk) => (
              <tr key={tk.id} className={tk.revoked_at !== null ? 'muted' : ''}>
                <td>
                  <bdi>{tk.name}</bdi>
                </td>
                <td>
                  <Ltr>{`dfk_${tk.prefix}_…`}</Ltr>
                </td>
                <td>{tk.owner}</td>
                <td>
                  <DateTime value={tk.created_at} />
                </td>
                <td>
                  <DateTime value={tk.expires_at} />
                </td>
                <td>
                  <DateTime value={tk.last_used_at} />
                </td>
                <td>
                  {tk.revoked_at !== null ? (
                    <span className="badge">{t('apidocs.tokens.revoked')}</span>
                  ) : (
                    <button
                      type="button"
                      className="danger"
                      onClick={() => {
                        void revoke(tk);
                      }}
                    >
                      {t('apidocs.tokens.revoke')}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function schemaLabel(p: Param): string {
  const s = p.schema ?? {};
  const choice = s.enum ?? s.anyOf?.find((x) => x.enum !== undefined)?.enum;
  if (choice !== undefined) return choice.join(' | ');
  return s.type ?? s.anyOf?.find((x) => x.type !== undefined && x.type !== 'null')?.type ?? 'string';
}

function Explorer() {
  const { t, tError } = useI18n();
  const schema = useApi<OpenApi>('/api/openapi.json');
  const [query, setQuery] = useState('');
  const [chosen, setChosen] = useState<string | null>(null);
  const endpoints = useMemo<Endpoint[]>(() => {
    const out: Endpoint[] = [];
    for (const [path, ops] of Object.entries(schema.data?.paths ?? {})) {
      if (ops.get !== undefined) out.push({ path, tag: ops.get.tags?.[0] ?? 'other', op: ops.get });
    }
    return out.sort((a, b) => a.tag.localeCompare(b.tag) || a.path.localeCompare(b.path));
  }, [schema.data]);
  const needle = query.trim().toLowerCase();
  const shown = endpoints.filter((e) => needle === '' || `${e.path} ${e.op.summary ?? ''}`.toLowerCase().includes(needle));
  const current = endpoints.find((e) => e.path === chosen) ?? null;
  const groups = [...new Set(shown.map((e) => e.tag))];

  return (
    <section className="apidocs-explorer">
      <div className="card apidocs-list">
        {schema.error !== null && <Alert kind="error">{tError(schema.error)}</Alert>}
        <input
          type="search"
          placeholder={t('apidocs.explorer.search')}
          aria-label={t('apidocs.explorer.search')}
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
          }}
        />
        <p className="muted small">{t('apidocs.explorer.count', { count: endpoints.length })}</p>
        {groups.map((g) => (
          <div key={g}>
            <h3 className="apidocs-tag">{g}</h3>
            <ul className="plain-list">
              {shown
                .filter((e) => e.tag === g)
                .map((e) => (
                  <li key={e.path}>
                    <button
                      type="button"
                      className={`link apidocs-path${e.path === chosen ? ' active' : ''}`}
                      onClick={() => {
                        setChosen(e.path);
                      }}
                    >
                      <span className="apidocs-get">GET</span> <Ltr>{e.path}</Ltr>
                    </button>
                  </li>
                ))}
            </ul>
          </div>
        ))}
      </div>
      <div className="card apidocs-detail">
        {current === null ? <p className="muted">{t('apidocs.explorer.pick')}</p> : <Try key={current.path} endpoint={current} />}
      </div>
    </section>
  );
}

function Try({ endpoint }: { endpoint: Endpoint }) {
  const { t } = useI18n();
  const params = (endpoint.op.parameters ?? []).filter((p) => p.in === 'path' || p.in === 'query');
  const [values, setValues] = useState<Record<string, string>>({});
  const [result, setResult] = useState<{ status: number; ms: number; body: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const missing = params.some((p) => p.in === 'path' && (values[p.name] ?? '').trim() === '');
  let url = endpoint.path;
  const search = new URLSearchParams();
  for (const p of params) {
    const v = (values[p.name] ?? '').trim();
    if (p.in === 'path') url = url.replace(`{${p.name}}`, encodeURIComponent(v === '' ? `{${p.name}}` : v));
    else if (v !== '') search.set(p.name, v);
  }
  const full = search.toString() === '' ? url : `${url}?${search.toString()}`;

  async function run() {
    setBusy(true);
    const started = performance.now();
    try {
      const resp = await fetch(full, { credentials: 'same-origin', headers: { Accept: 'application/json' }, cache: 'no-store', redirect: 'error' });
      const text = await resp.text();
      let pretty = text;
      try {
        pretty = JSON.stringify(JSON.parse(text) as unknown, null, 2);
      } catch {
        // not JSON: shown as it came
      }
      setResult({ status: resp.status, ms: Math.round(performance.now() - started), body: pretty.slice(0, MAX_SHOWN) });
    } catch (err) {
      setResult({ status: 0, ms: Math.round(performance.now() - started), body: String(err) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack">
      <h2>
        <span className="apidocs-get">GET</span> <Ltr>{endpoint.path}</Ltr>
      </h2>
      {endpoint.op.summary !== undefined && <p>{endpoint.op.summary}</p>}
      {endpoint.op.description !== undefined && <p className="muted small">{endpoint.op.description}</p>}
      {params.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>{t('apidocs.explorer.param')}</th>
              <th>{t('apidocs.explorer.type')}</th>
              <th>{t('apidocs.explorer.value')}</th>
            </tr>
          </thead>
          <tbody>
            {params.map((p) => (
              <tr key={`${p.in}-${p.name}`}>
                <td>
                  <code className="ltr">{p.name}</code> <span className="muted small">{p.in}</span>
                  {p.required === true && <span className="bad"> *</span>}
                </td>
                <td className="small">
                  <Ltr>{schemaLabel(p)}</Ltr>
                </td>
                <td>
                  <input
                    dir="ltr"
                    aria-label={p.name}
                    value={values[p.name] ?? ''}
                    onChange={(e) => {
                      setValues({ ...values, [p.name]: e.target.value });
                    }}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="row">
        <button type="button" disabled={busy || missing} onClick={() => void run()}>
          {t('apidocs.explorer.run')}
        </button>
        <code className="ltr small">{full}</code>
      </div>
      <pre className="apidocs-code" dir="ltr">{`curl -s -H "Authorization: Bearer $DF_TOKEN" "${window.location.origin}${full}"`}</pre>
      {result !== null && (
        <>
          <p className={result.status >= 200 && result.status < 300 ? 'ok' : 'bad'}>
            {t('apidocs.explorer.status', { status: result.status, ms: result.ms })}
          </p>
          <pre className="apidocs-code apidocs-response" dir="ltr">
            {result.body}
          </pre>
        </>
      )}
    </div>
  );
}

function Reference() {
  const { t } = useI18n();
  return (
    <section className="stack">
      <div className="card">
        <h2>{t('apidocs.ref.findings')}</h2>
        <table>
          <thead>
            <tr>
              <th>{t('apidocs.ref.code')}</th>
              <th>{t('apidocs.ref.name')}</th>
              <th>{t('apidocs.ref.why')}</th>
              <th>{t('apidocs.ref.fix')}</th>
            </tr>
          </thead>
          <tbody>
            {FINDING_KINDS.map((k) => {
              const why = `finding.${k}.why`;
              const fix = `finding.${k}.fix`;
              return (
                <tr key={k}>
                  <td>
                    <code className="ltr">{k}</code>
                  </td>
                  <td>{t(`findings.kind.${k}`)}</td>
                  <td className="small">{isMessageKey(why) ? t(why) : '—'}</td>
                  <td className="small">{isMessageKey(fix) ? t(fix) : '—'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div className="card">
        <h2>{t('apidocs.ref.recommendations')}</h2>
        <table>
          <thead>
            <tr>
              <th>{t('apidocs.ref.code')}</th>
              <th>{t('apidocs.ref.name')}</th>
              <th>{t('apidocs.ref.phase')}</th>
              <th>{t('apidocs.ref.traffic')}</th>
            </tr>
          </thead>
          <tbody>
            {RECOMMENDATION_KINDS.map((k) => (
              <tr key={k}>
                <td>
                  <code className="ltr">{k}</code>
                </td>
                <td>{t(`rec.kind.${k}`)}</td>
                <td>{t(`road.phase.${phaseOf(k)}`)}</td>
                <td>{CHANGING_KINDS.has(k) ? <span className="warn">{t('road.behavior.changes')}</span> : t('road.behavior.preserves')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
