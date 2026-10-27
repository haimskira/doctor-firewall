import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

import type { FindingRow } from '../api/types';
import { isMessageKey, useI18n } from '../i18n/I18nProvider';
import { DateTime, Ltr } from './common';

/* Plain-language view of a finding: what was found, why it matters, what to do. The details
   come from the analysis as untrusted JSON, so every value is checked before use and shown as
   text (React escapes it); internal ids are only used to build links, never displayed. */

type Json = Record<string, unknown>;

interface RuleRef {
  id: string;
  name: string;
  index: number;
}

interface NamedRef {
  id: string | null;
  name: string;
}

const DEEP_NESTING_LIMIT = 3;

function obj(value: unknown): Json | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Json) : null;
}

function str(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function num(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function rule(value: unknown): RuleRef | null {
  const j = obj(value);
  const id = str(j?.['id']);
  const name = str(j?.['name']);
  const index = num(j?.['index']);
  return id !== null && name !== null && index !== null ? { id, name, index } : null;
}

function named(value: unknown): NamedRef | null {
  const literal = str(obj(value)?.['literal']);
  if (literal !== null) return { id: null, name: literal };
  const j = obj(value);
  const name = str(j?.['name']);
  return name !== null ? { id: str(j?.['id']), name } : null;
}

function present<T>(values: (T | null)[]): T[] {
  return values.filter((v): v is T => v !== null);
}

function fmt(n: number): string {
  return n.toLocaleString();
}

interface Links {
  snapshotId: number;
  policyId: string | null;
}

function RuleLink({ r, links }: { r: RuleRef; links: Links }) {
  const label = `#${String(r.index)} ${r.name}`;
  if (links.policyId === null) return <bdi>{label}</bdi>;
  const to = `/rules?snapshot=${String(links.snapshotId)}&policy=${encodeURIComponent(links.policyId)}&q=${encodeURIComponent(r.name)}`;
  return (
    <Link to={to}>
      <bdi>{label}</bdi>
    </Link>
  );
}

function ObjectLink({ o, links }: { o: NamedRef; links: Links }) {
  if (o.id === null) return <Ltr>{o.name}</Ltr>;
  return (
    <Link to={`/objects/explore?snapshot=${String(links.snapshotId)}&object=${encodeURIComponent(o.id)}`}>
      <bdi>{o.name}</bdi>
    </Link>
  );
}

function Items({ children }: { children: ReactNode[] }) {
  return <ul className="finding-items">{children}</ul>;
}

function Section({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="finding-section">
      <h4>{label}</h4>
      {children}
    </div>
  );
}

/** The localised one-line headline of a finding (falls back to the analysis title). */
export function useFindingHeadline(): (f: FindingRow) => string {
  const { t } = useI18n();
  return (f) => {
    const d = f.details;
    const r = rule(d['rule']);
    const ruleLabel = r === null ? '' : `#${String(r.index)} ${r.name}`;
    switch (f.kind) {
      case 'ace_cluster_limit': {
        const aces = num(d['aces']);
        const limit = num(d['limit']);
        const cluster = str(obj(d['cluster'])?.['name']);
        if (aces === null || limit === null || cluster === null || limit <= 0) break;
        return t('finding.ace_cluster_limit.head', {
          cluster,
          aces: fmt(aces),
          limit: fmt(limit),
          pct: Math.round((aces * 100) / limit),
        });
      }
      case 'shadowed_rule':
      case 'dead_rule':
      case 'overlap_conflict':
        if (r === null) break;
        return t(`finding.${f.kind}.head`, { rule: ruleLabel });
      case 'ace_heavy_rule': {
        const aces = num(d['aces']);
        if (r === null || aces === null) break;
        return t('finding.ace_heavy_rule.head', { rule: ruleLabel, aces: fmt(aces) });
      }
      case 'identical_rules':
        return t('finding.identical_rules.head', { count: list(d['rules']).length });
      case 'group_cycle':
        return t('finding.group_cycle.head', {
          cycle: present(list(d['groups']).map(named))
            .map((g) => g.name)
            .join(' → '),
        });
      case 'deep_nesting': {
        const group = named(d['group']);
        const depth = num(d['depth']);
        if (group === null || depth === null) break;
        return t('finding.deep_nesting.head', { group: group.name, depth });
      }
      case 'duplicate_membership': {
        const group = named(d['group']);
        if (group !== null) {
          return t('finding.duplicate_membership.headGroup', { group: group.name, count: list(d['members']).length });
        }
        if (r === null) break;
        return t('finding.duplicate_membership.headRule', { rule: ruleLabel });
      }
      case 'duplicate_object': {
        const value = str(d['value']);
        if (value === null) break;
        return t('finding.duplicate_object.head', { count: list(d['objects']).length, value });
      }
      case 'inline_literal': {
        const literal = str(d['literal']);
        if (literal === null) break;
        if (d['where'] === 'route') return t('finding.inline_literal.headRoute', { literal });
        if (d['where'] === 'group') {
          return t('finding.inline_literal.headGroup', { literal, count: list(d['groups']).length });
        }
        return t('finding.inline_literal.headRule', { literal, count: list(d['rules']).length });
      }
      case 'unused_object': {
        const o = named(d['object']);
        if (o === null) break;
        return t('finding.unused_object.head', { name: o.name });
      }
      default:
        break;
    }
    return f.title;
  };
}

export function FindingDetails({ finding, snapshotId }: { finding: FindingRow; snapshotId: number }) {
  const { t } = useI18n();
  const d = finding.details;
  const links: Links = { snapshotId, policyId: finding.policy_fmc_id };
  const r = rule(d['rule']);
  const body: ReactNode[] = [];

  switch (finding.kind) {
    case 'ace_cluster_limit': {
      const aces = num(d['aces']);
      const limit = num(d['limit']);
      const cluster = obj(d['cluster']);
      if (aces === null || limit === null || limit <= 0) break;
      const pct = Math.round((aces * 100) / limit);
      const band = pct > 100 ? 'bad' : pct > 80 ? 'warn' : 'good';
      body.push(
        <div key="gauge" className="finding-gauge">
          <div
            className={`gauge gauge-${band}`}
            role="meter"
            aria-valuemin={0}
            aria-valuemax={limit}
            aria-valuenow={aces}
            aria-label={t('finding.ace_cluster_limit.gauge')}
          >
            <span style={{ inlineSize: `${String(Math.min(pct, 100))}%` }} />
          </div>
          <span>{t('finding.ace_cluster_limit.usage', { aces: fmt(aces), limit: fmt(limit), pct })}</span>
        </div>,
      );
      const clusterId = str(cluster?.['id']);
      body.push(
        <p key="limit">
          {d['limit_verified'] === true ? t('finding.ace_cluster_limit.verified') : t('finding.ace_cluster_limit.unverified', { limit: fmt(limit) })}{' '}
          {clusterId !== null && (
            <Link to={`/clusters?snapshot=${String(snapshotId)}&cluster=${encodeURIComponent(clusterId)}`}>
              {t('finding.ace_cluster_limit.setLimit')}
            </Link>
          )}
        </p>,
      );
      break;
    }
    case 'shadowed_rule': {
      const by = rule(d['by']);
      if (r === null || by === null) break;
      body.push(
        <p key="what">
          {t('finding.shadowed_rule.by')} <RuleLink r={by} links={links} />
          {d['conflict'] === true && <strong> {t('finding.shadowed_rule.conflict')}</strong>}
        </p>,
        <p key="rule">
          {t('finding.rule')}: <RuleLink r={r} links={links} />
        </p>,
      );
      break;
    }
    case 'overlap_conflict': {
      const other = rule(d['with']);
      if (r === null || other === null) break;
      body.push(
        <p key="what">
          {t('finding.overlap_conflict.with')} <RuleLink r={other} links={links} />
        </p>,
        <p key="rule">
          {t('finding.rule')}: <RuleLink r={r} links={links} />
        </p>,
      );
      break;
    }
    case 'dead_rule': {
      if (r === null) break;
      const hits = num(d['hit_count']);
      const last = str(d['last_hit']);
      body.push(
        <p key="rule">
          {t('finding.rule')}: <RuleLink r={r} links={links} />
        </p>,
        <p key="hits">
          {t('finding.dead_rule.hits', { hits: hits === null ? '—' : fmt(hits) })} · {t('finding.dead_rule.lastHit')}:{' '}
          {last === null ? t('finding.dead_rule.never') : <DateTime value={last} />}
        </p>,
      );
      break;
    }
    case 'ace_heavy_rule': {
      if (r === null) break;
      const leaves = Object.entries(obj(d['leaves']) ?? {}).flatMap(([field, n]) => {
        const count = num(n);
        return count === null || count === 0 ? [] : [[field, count] as const];
      });
      body.push(
        <p key="rule">
          {t('finding.rule')}: <RuleLink r={r} links={links} />
        </p>,
      );
      if (leaves.length > 0) {
        body.push(
          <p key="factors" className="finding-factors">
            {leaves.map(([field, count], i) => {
              const key = `field.${field}`;
              return (
                <span key={field}>
                  {i > 0 && ' × '}
                  {fmt(count)} {isMessageKey(key) ? t(key) : field}
                </span>
              );
            })}
          </p>,
        );
      }
      break;
    }
    case 'identical_rules': {
      const rules = present(list(d['rules']).map(rule));
      body.push(
        <Section key="rules" label={t('finding.rules')}>
          <Items>
            {rules.map((x) => (
              <li key={x.id}>
                <RuleLink r={x} links={links} />
              </li>
            ))}
          </Items>
        </Section>,
      );
      break;
    }
    case 'group_cycle':
    case 'deep_nesting':
    case 'unused_object': {
      const groups =
        finding.kind === 'group_cycle'
          ? present(list(d['groups']).map(named))
          : present([named(finding.kind === 'deep_nesting' ? d['group'] : d['object'])]);
      body.push(
        <p key="objects" className="finding-chain">
          {groups.map((g, i) => (
            <span key={`${g.id ?? g.name}-${String(i)}`}>
              {i > 0 && ' → '}
              <ObjectLink o={g} links={links} />
            </span>
          ))}
          {finding.kind === 'group_cycle' && groups[0] !== undefined && (
            <span>
              {' → '}
              <bdi>{groups[0].name}</bdi>
            </span>
          )}
        </p>,
      );
      if (finding.kind === 'deep_nesting') {
        body.push(<p key="depth">{t('finding.deep_nesting.depth', { depth: num(d['depth']) ?? '—', limit: DEEP_NESTING_LIMIT })}</p>);
      }
      break;
    }
    case 'duplicate_membership': {
      const group = named(d['group']);
      const member = (m: unknown, n: number) => {
        const ref = named(m);
        const paths = num(obj(m)?.['paths']);
        if (ref === null) return null;
        return (
          <li key={`${ref.id ?? ref.name}-${String(n)}`}>
            <ObjectLink o={ref} links={links} />
            {paths !== null && <span className="muted"> · {t('finding.duplicate_membership.paths', { paths })}</span>}
          </li>
        );
      };
      if (group !== null) {
        body.push(
          <p key="group">
            {t('finding.group')}: <ObjectLink o={group} links={links} />
          </p>,
          <Section key="members" label={t('finding.duplicate_membership.members')}>
            <Items>{present(list(d['members']).map(member))}</Items>
          </Section>,
        );
      } else if (r !== null) {
        body.push(
          <p key="rule">
            {t('finding.rule')}: <RuleLink r={r} links={links} />
          </p>,
        );
        for (const [n, fieldValue] of list(d['fields']).entries()) {
          const field = str(obj(fieldValue)?.['field']) ?? '';
          const key = `field.${field}`;
          body.push(
            <Section key={`f-${String(n)}`} label={isMessageKey(key) ? t(key) : field}>
              <Items>{present(list(obj(fieldValue)?.['members']).map(member))}</Items>
            </Section>,
          );
        }
      }
      break;
    }
    case 'duplicate_object': {
      const objects = present(list(d['objects']).map(named));
      body.push(
        <Section key="objects" label={t('finding.objects')}>
          <Items>
            {objects.map((o) => (
              <li key={o.id ?? o.name}>
                <ObjectLink o={o} links={links} />
              </li>
            ))}
          </Items>
        </Section>,
      );
      break;
    }
    case 'inline_literal': {
      if (d['where'] === 'route') {
        const routes = present(
          list(d['routes']).map((x) => {
            const j = obj(x);
            return j === null ? null : { cluster: str(j['cluster_name']) ?? '—', iface: str(j['interface']) ?? '—', network: str(j['network']) ?? '—' };
          }),
        );
        body.push(
          <Section key="routes" label={t('finding.routes')}>
            <Items>
              {routes.map((x, n) => (
                <li key={String(n)}>
                  <bdi>{x.cluster}</bdi> · <Ltr>{x.iface}</Ltr> · <bdi>{x.network}</bdi>
                </li>
              ))}
            </Items>
          </Section>,
        );
      } else if (d['where'] === 'group') {
        body.push(
          <Section key="groups" label={t('finding.groups')}>
            <Items>
              {present(list(d['groups']).map(named)).map((g) => (
                <li key={g.id ?? g.name}>
                  <ObjectLink o={g} links={links} />
                </li>
              ))}
            </Items>
          </Section>,
        );
      } else {
        body.push(
          <Section key="rules" label={t('finding.rules')}>
            <Items>
              {list(d['rules']).map((x, n) => {
                const ref = rule(x);
                const field = str(obj(x)?.['field']) ?? '';
                const key = `field.${field}`;
                return ref === null ? null : (
                  <li key={`${ref.id}-${String(n)}`}>
                    <RuleLink r={ref} links={links} /> <span className="muted">· {isMessageKey(key) ? t(key) : field}</span>
                  </li>
                );
              })}
            </Items>
          </Section>,
        );
      }
      break;
    }
    default:
      break;
  }

  const why = `finding.${finding.kind}.why`;
  const fix = `finding.${finding.kind}.fix`;
  return (
    <div className="finding-detail">
      {body}
      {isMessageKey(why) && (
        <p className="muted">
          <strong>{t('finding.whyLabel')}</strong> {t(why)}
        </p>
      )}
      {isMessageKey(fix) && (
        <p>
          <strong>{t('finding.fixLabel')}</strong> {t(fix)}{' '}
          <Link to={`/recommendations?snapshot=${String(snapshotId)}`}>{t('finding.toRecommendations')}</Link>
        </p>
      )}
    </div>
  );
}
