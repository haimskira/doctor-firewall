import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { api, errorCode } from '../api/client';
import type { AuditVerify, DashboardData, FmcConnection, MapRisk, Severity } from '../api/types';
import { useAuth, useMe } from '../auth/AuthProvider';
import { Alert, DateTime, Ltr } from '../components/common';
import { BarTable, Figures, Widget, useRelativeTime } from '../components/dashboard';
import type { BarRow, BarTone } from '../components/dashboard';
import { SnapshotPicker } from '../components/inventory';
import { useNodeLabel } from '../components/mapParts';
import { useApi, useQueryParam, useSnapshotSelection } from '../hooks';
import { PolicyPicker, ScopeNote, usePolicyScope } from '../components/policyScope';
import { isMessageKey, useI18n } from '../i18n/I18nProvider';
import type { MessageKey } from '../i18n/messages';

const TABS = ['overview', 'risk', 'recommendations', 'status'] as const;
type Tab = (typeof TABS)[number];

// Web storage is forbidden by policy: closed widgets are remembered for this session only.
const WIDGETS = new Map<Tab, readonly string[]>(Object.entries({
  overview: ['totals', 'findings', 'scores', 'ace', 'actions', 'recommendations'],
  risk: ['connections', 'worst', 'maprisk', 'severity'],
  recommendations: ['recCount', 'recCost'],
  status: ['snapshot', 'fmc', 'audit', 'access'],
} satisfies Record<Tab, readonly string[]>) as [Tab, readonly string[]][]);
const SEVERITY_TONES = new Map<Severity, BarTone>([
  ['high', 'red'],
  ['medium', 'orange'],
  ['low', 'yellow'],
  ['info', 'gray'],
]);
const RISK_TONES = new Map<MapRisk, BarTone>([
  ['red', 'red'],
  ['yellow', 'yellow'],
  ['green', 'green'],
]);
const SCORE_TONES: readonly BarTone[] = ['red', 'orange', 'yellow', 'blue', 'green'];

function label(t: (k: MessageKey) => string, key: string, raw: string): string {
  return isMessageKey(key) ? t(key) : raw;
}

/** Summary dashboard in the FMC style: tabs of closable widgets over the latest analysis. */
export function HomePage() {
  const { t, tError } = useI18n();
  const { snapshots, snapshotId, setSnapshotId, error: snapError } = useSnapshotSelection();
  const [tabParam, setTab] = useQueryParam('tab');
  const tab: Tab = TABS.find((x) => x === tabParam) ?? 'overview';
  const [hidden, setHidden] = useState<Set<string>>(() => new Set());
  const [adding, setAdding] = useState(false);
  const scope = usePolicyScope(snapshotId);
  const data = useApi<DashboardData>(
    snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}/dashboard${scope.policy === null ? '' : `?policy=${scope.policy}`}`,
  );
  const since = useRelativeTime();
  const nodeLabel = useNodeLabel();
  const d = data.data;
  const footer = t('dash.updated', { when: since(d?.snapshot.analyzed_at ?? null) });
  const q = snapshotId === null ? '' : `snapshot=${String(snapshotId)}`;

  function hide(id: string) {
    const next = new Set(hidden);
    next.add(id);
    setHidden(next);
  }

  function restore(id: string) {
    const next = new Set(hidden);
    next.delete(id);
    setHidden(next);
  }

  const ids = WIDGETS.get(tab) ?? [];
  const shown = ids.filter((w) => !hidden.has(w));
  const missing = ids.filter((w) => hidden.has(w));
  const close = (id: string) => () => {
    hide(id);
  };

  function widget(id: string) {
    if (id === 'snapshot' || id === 'fmc' || id === 'audit' || id === 'access') {
      return <StatusWidget key={id} id={id} data={d} onClose={close(id)} />;
    }
    if (d === null) return null;
    const title = t(`dash.w.${id}` as MessageKey);
    switch (id) {
      case 'totals':
        return (
          <Widget key={id} title={title} footer={footer} onClose={close(id)}>
            <Figures
              items={[
                { key: 'rules', label: t('dash.t.rules'), value: d.totals.rules, to: `/rules?${q}` },
                { key: 'policies', label: t('dash.t.policies'), value: d.totals.policies, to: `/policies?${q}` },
                { key: 'objects', label: t('dash.t.objects'), value: d.totals.objects, to: `/objects?${q}` },
                { key: 'clusters', label: t('dash.t.clusters'), value: d.totals.clusters, to: `/clusters?${q}` },
                { key: 'shadowed', label: t('dash.t.shadowed'), value: d.totals.shadowed_rules, to: `/findings?${q}&kind=shadowed_rule` },
                { key: 'dead', label: t('dash.t.dead'), value: d.totals.dead_rules, to: `/findings?${q}&kind=dead_rule` },
              ]}
            />
          </Widget>
        );
      case 'findings':
        return (
          <Widget key={id} title={title} footer={footer} onClose={close(id)}>
            <BarTable
              labelHeader={t('dash.h.type')}
              valueHeader={t('dash.h.count')}
              empty={t('dash.empty')}
              tone="blue"
              rows={d.findings_by_kind.slice(0, 12).map((f) => ({
                key: f.key,
                label: label(t, `findings.kind.${f.key}`, f.key),
                value: f.count,
                to: `/findings?${q}&kind=${f.key}`,
                fix: findingFix(f.key, q, t('dash.fix')),
              }))}
            />
          </Widget>
        );
      case 'scores':
        return (
          <Widget key={id} title={title} footer={footer} onClose={close(id)}>
            <BarTable
              labelHeader={t('dash.h.score')}
              valueHeader={t('dash.h.rules')}
              empty={t('dash.empty')}
              rows={d.score_buckets.map((b, i) => ({
                key: b.key,
                label: <Ltr>{b.key}</Ltr>,
                value: b.count,
                tone: SCORE_TONES.at(i) ?? 'blue',
              }))}
            />
          </Widget>
        );
      case 'ace':
        return (
          <Widget key={id} title={title} footer={footer} onClose={close(id)}>
            <BarTable
              labelHeader={t('dash.h.cluster')}
              valueHeader={t('dash.h.aceUsage')}
              empty={t('dash.empty')}
              rows={d.clusters.map((c) => {
                const pct = c.ace_total === null ? 0 : Math.round((c.ace_total / c.ace_limit) * 100);
                return {
                  key: c.id,
                  label: <Ltr>{c.name}</Ltr>,
                  value: pct,
                  display: `${String(pct)}%${c.ace_limit_verified ? '' : ' *'}`,
                  tone: pct >= 100 ? 'red' : pct >= 80 ? 'orange' : 'green',
                  to: `/clusters?${q}`,
                } satisfies BarRow;
              })}
            />
            {d.clusters.some((c) => !c.ace_limit_verified) && <p className="widget-note">* {t('dash.limitNote')}</p>}
          </Widget>
        );
      case 'actions':
        return (
          <Widget key={id} title={title} footer={footer} onClose={close(id)}>
            <BarTable
              labelHeader={t('rules.col.action')}
              valueHeader={t('dash.h.rules')}
              empty={t('dash.empty')}
              rows={d.rules_by_action.map((a) => ({
                key: a.key,
                label: <Ltr>{a.key}</Ltr>,
                value: a.count,
                tone: a.key.startsWith('BLOCK') ? 'red' : a.key === 'ALLOW' || a.key === 'TRUST' ? 'green' : 'gray',
              }))}
            />
          </Widget>
        );
      case 'recommendations':
      case 'recCount':
        return (
          <Widget key={id} title={title} footer={footer} onClose={close(id)}>
            <BarTable
              labelHeader={t('dash.h.type')}
              valueHeader={t('dash.h.count')}
              empty={t('dash.empty')}
              tone="green"
              rows={d.recommendations_by_kind.map((r) => ({
                key: r.key,
                label: label(t, `rec.kind.${r.key}`, r.key),
                value: r.count,
                to: `/recommendations?${q}&kind=${r.key}`,
              }))}
            />
          </Widget>
        );
      case 'recCost':
        return (
          <Widget key={id} title={title} footer={footer} onClose={close(id)}>
            <BarTable
              labelHeader={t('dash.h.type')}
              valueHeader={t('rec.col.cost')}
              empty={t('dash.empty')}
              tone="orange"
              rows={[...d.recommendations_by_kind]
                .sort((a, b) => (b.extra['deploy_cost'] ?? 0) - (a.extra['deploy_cost'] ?? 0))
                .map((r) => ({
                  key: r.key,
                  label: label(t, `rec.kind.${r.key}`, r.key),
                  value: r.extra['deploy_cost'] ?? 0,
                  to: `/recommendations?${q}&kind=${r.key}`,
                }))}
            />
          </Widget>
        );
      case 'connections':
        return (
          <Widget key={id} title={title} footer={footer} onClose={close(id)} wide>
            <BarTable
              labelHeader={t('dash.h.connection')}
              valueHeader={t('dash.h.rules')}
              empty={t('dash.empty')}
              rows={d.riskiest_connections.map((c) => ({
                key: `${c.src}->${c.dst}`,
                label: (
                  <>
                    <Ltr>{nodeLabel(c.src)}</Ltr> → <Ltr>{nodeLabel(c.dst)}</Ltr>
                  </>
                ),
                value: c.rule_count,
                tone: RISK_TONES.get(c.risk) ?? 'gray',
                to: `/map?${q}`,
              }))}
            />
          </Widget>
        );
      case 'worst':
        return (
          <Widget key={id} title={title} footer={footer} onClose={close(id)}>
            <BarTable
              labelHeader={t('dash.h.rule')}
              valueHeader={t('score.col')}
              empty={t('dash.empty')}
              tone="pink"
              rows={d.worst_rules.map((r) => ({
                key: `${r.policy_id}-${r.id}`,
                label: (
                  <>
                    #{r.index} <Ltr>{r.name}</Ltr>
                  </>
                ),
                value: 100 - r.score,
                display: String(r.score),
                to: `/rules?${q}&policy=${encodeURIComponent(r.policy_id)}&q=${encodeURIComponent(r.name)}`,
              }))}
            />
          </Widget>
        );
      case 'maprisk':
        return (
          <Widget key={id} title={title} footer={footer} onClose={close(id)}>
            <BarTable
              labelHeader={t('map.col.risk')}
              valueHeader={t('dash.h.connections')}
              empty={t('dash.empty')}
              rows={(['red', 'yellow', 'green'] as const).map((r) => ({
                key: r,
                label: t(`map.risk.${r}`),
                value: new Map(Object.entries(d.map_risk)).get(r) ?? 0,
                tone: RISK_TONES.get(r) ?? 'gray',
                to: `/map?${q}&risk=${r}`,
              }))}
            />
          </Widget>
        );
      case 'severity':
        return (
          <Widget key={id} title={title} footer={footer} onClose={close(id)}>
            <BarTable
              labelHeader={t('findings.severity')}
              valueHeader={t('dash.h.count')}
              empty={t('dash.empty')}
              rows={(['high', 'medium', 'low', 'info'] as const).map((s) => ({
                key: s,
                label: t(`findings.sev.${s}`),
                value: new Map(Object.entries(d.findings_by_severity)).get(s) ?? 0,
                tone: SEVERITY_TONES.get(s) ?? 'gray',
                to: `/findings?${q}&severity=${s}`,
              }))}
            />
          </Widget>
        );
      default:
        return null;
    }
  }

  return (
    <div className="dash">
      <div className="dash-head">
        <div>
          <div className="dash-title">
            <h1>{t('dash.title')}</h1>
            <SnapshotPicker snapshots={snapshots} value={snapshotId} onChange={setSnapshotId} />
        <PolicyPicker scope={scope} />
          </div>
      <ScopeNote scope={scope} />
          <p className="muted">{t('dash.subtitle')}</p>
        </div>
      </div>
      {(snapError ?? data.error) !== null && <Alert kind="error">{tError(snapError ?? data.error ?? '')}</Alert>}
      {snapshotId === null && snapError === null && tab !== 'status' && <Alert kind="info">{t('snap.none')}</Alert>}

      <div className="pe-flow dash-tabs" role="tablist" aria-label={t('dash.title')}>
        {TABS.map((x) => (
          <button
            key={x}
            type="button"
            role="tab"
            aria-selected={tab === x}
            className={tab === x ? 'active' : ''}
            onClick={() => {
              setTab(x === 'overview' ? null : x);
              setAdding(false);
            }}
          >
            {t(`dash.tab.${x}`)}
          </button>
        ))}
      </div>

      <div className="dash-board">
        <div className="dash-toolbar">
          {missing.length > 0 && (
            <div className="dash-add">
              <button
                type="button"
                className="secondary"
                aria-expanded={adding}
                onClick={() => {
                  setAdding(!adding);
                }}
              >
                {t('dash.addWidgets')}
              </button>
              {adding && (
                <div className="fmc-menu" role="menu">
                  {missing.map((w) => (
                    <button
                      key={w}
                      type="button"
                      role="menuitem"
                      onClick={() => {
                        restore(w);
                        setAdding(false);
                      }}
                    >
                      {t(`dash.w.${w}` as MessageKey)}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
        <div className="widget-grid">{shown.map((w) => widget(w))}</div>
      </div>
    </div>
  );
}

function StatusWidget({ id, data, onClose }: { id: string; data: DashboardData | null; onClose: () => void }) {
  const { t, tError } = useI18n();
  const { can } = useAuth();
  const me = useMe();
  const [connections, setConnections] = useState<FmcConnection[] | null>(null);
  const [verify, setVerify] = useState<AuditVerify | null>(null);
  const [error, setError] = useState<string | null>(null);
  const canFmc = can('fmc:manage');

  useEffect(() => {
    if (id !== 'fmc' || !canFmc) return;
    api<FmcConnection[]>('/api/fmc/connections')
      .then(setConnections)
      .catch((err: unknown) => {
        setError(tError(errorCode(err)));
      });
  }, [id, canFmc, tError]);

  async function runVerify() {
    setError(null);
    try {
      setVerify(await api<AuditVerify>('/api/audit/verify', 'POST'));
    } catch (err: unknown) {
      setError(tError(errorCode(err)));
    }
  }

  if (id === 'snapshot') {
    if (data === null) return null;
    const s = data.snapshot;
    return (
      <Widget title={t('dash.w.snapshot')} onClose={onClose}>
        <dl className="kv">
          <dt>{t('nav.fmc')}</dt>
          <dd>
            <Ltr>{s.connection_name}</Ltr>
          </dd>
          <dt>{t('dash.fmcVersion')}</dt>
          <dd>
            <Ltr>{s.fmc_version ?? '—'}</Ltr>
          </dd>
          <dt>{t('dash.collected')}</dt>
          <dd>
            <DateTime value={s.finished_at} />
          </dd>
          <dt>{t('dash.analysed')}</dt>
          <dd>
            <DateTime value={s.analyzed_at} />
          </dd>
        </dl>
        <Link to="/snapshots">{t('nav.snapshots')}</Link>
      </Widget>
    );
  }
  if (id === 'fmc') {
    if (!canFmc) return null;
    return (
      <Widget title={t('home.fmcStatus')} onClose={onClose}>
        {error !== null && <Alert kind="error">{error}</Alert>}
        {connections === null && error === null && <p className="muted">{t('common.loading')}</p>}
        {connections?.length === 0 && (
          <p>
            {t('home.fmcNone')} <Link to="/fmc">{t('fmc.add')}</Link>
          </p>
        )}
        {connections?.map((c) => (
          <p key={c.id}>
            <strong>{c.name}</strong> —{' '}
            <Ltr>
              {c.host}:{c.port}
            </Ltr>{' '}
            · {t('fmc.lastTest')}: <DateTime value={c.last_test_at} />{' '}
            {c.last_test_ok === true && <span className="ok">✔</span>}
            {c.last_test_ok === false && <span className="bad">✘</span>}
          </p>
        ))}
      </Widget>
    );
  }
  if (id === 'audit') {
    if (!can('audit:read')) return null;
    return (
      <Widget title={t('home.auditStatus')} onClose={onClose}>
        {error !== null && <Alert kind="error">{error}</Alert>}
        <button type="button" className="secondary" onClick={() => void runVerify()}>
          {t('home.auditVerify')}
        </button>
        {verify?.ok === true && <Alert kind="success">{t('audit.verifyOk', { count: verify.checked })}</Alert>}
        {verify?.ok === false && (
          <Alert kind="error">
            {t('audit.verifyBroken', { id: verify.broken_at_id ?? '?', reason: verify.reason ?? '?' })}
          </Alert>
        )}
      </Widget>
    );
  }
  return (
    <Widget title={t('home.welcome', { name: me.display_name || me.username })} onClose={onClose}>
      <h3>{t('home.roles')}</h3>
      <ul className="chips">
        {me.roles.map((role) => (
          <li key={role} className="chip">
            {t(`role.${role}`)}
          </li>
        ))}
      </ul>
      <h3>{t('home.permissions')}</h3>
      <ul className="plain-list small">
        {me.permissions.map((perm) => (
          <li key={perm}>{t(`perm.${perm}`)}</li>
        ))}
      </ul>
    </Widget>
  );
}

/** The recommendations that fix a finding type (none: the finding page explains why). */
const FINDING_FIXES = new Map<string, string>([
  ['shadowed_rule', 'kind=remove_shadowed_rule'],
  ['identical_rules', 'kind=remove_shadowed_rule'],
  ['dead_rule', 'kind=remove_dead_rule'],
  ['disabled_rule', 'kind=remove_disabled_rule'],
  ['unused_object', 'kind=remove_unused_object'],
  ['duplicate_object', 'kind=merge_duplicate_objects'],
  ['duplicate_membership', 'kind=remove_redundant_member'],
  ['inline_literal', 'kind=literal_to_object'],
  ['ace_heavy_rule', 'kind=compact_group'],
  ['ace_cluster_limit', 'sort=ace_delta&order=asc'],
]);

function findingFix(kind: string, q: string, label: string): { to: string; label: string } | undefined {
  const filter = FINDING_FIXES.get(kind);
  return filter === undefined ? undefined : { to: `/recommendations?${q}&${filter}`, label };
}
