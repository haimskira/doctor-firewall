import type { MapEdge, MapRisk } from '../api/types';
import { useI18n } from '../i18n/I18nProvider';
import { Ltr } from './common';
import type { FlowMetric } from './FlowSankey';

const TOP = 6;

function metricOf(e: MapEdge, metric: FlowMetric): number {
  return metric === 'hits' ? e.hits : e.rule_count;
}

function riskCount(e: MapEdge, risk: MapRisk): number {
  return new Map(Object.entries(e.risk_rules)).get(risk) ?? (e.risk === risk ? e.rule_count : 0);
}

/** "Top N" panels next to the flow view (riskiest connections, busiest targets, services). */
export function FlowInsights({
  edges,
  metric,
  nodeLabel,
  onSelectEdge,
  onSelectNode,
}: {
  edges: MapEdge[];
  metric: FlowMetric;
  nodeLabel: (id: string) => string;
  onSelectEdge: (id: string) => void;
  onSelectNode: (id: string) => void;
}) {
  const { t } = useI18n();
  const risky = [...edges]
    .filter((e) => riskCount(e, 'red') > 0)
    .sort((a, b) => riskCount(b, 'red') - riskCount(a, 'red'))
    .slice(0, TOP);
  const targets = new Map<string, number>();
  const services = new Map<string, number>();
  for (const e of edges) {
    targets.set(e.dst, (targets.get(e.dst) ?? 0) + metricOf(e, metric));
    for (const s of e.services) services.set(s, (services.get(s) ?? 0) + 1);
  }
  const top = (m: Map<string, number>) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, TOP);
  const topTargets = top(targets);
  const topServices = top(services);
  const max = (rows: [string, number][]) => Math.max(1, ...rows.map(([, v]) => v));

  return (
    <div className="flow-insights">
      <section className="card">
        <h3>{t('map.insight.risky')}</h3>
        {risky.length === 0 ? (
          <p className="muted small">{t('map.insight.noRisky')}</p>
        ) : (
          <ol className="insight-list">
            {risky.map((e) => (
              <li key={e.id}>
                <button type="button" className="link" onClick={() => { onSelectEdge(e.id); }}>
                  <Ltr>{nodeLabel(e.src)}</Ltr> → <Ltr>{nodeLabel(e.dst)}</Ltr>
                </button>
                <span className="insight-value risk-text-red">{t('map.insight.redRules', { count: riskCount(e, 'red') })}</span>
              </li>
            ))}
          </ol>
        )}
      </section>
      <section className="card">
        <h3>{t(metric === 'hits' ? 'map.insight.busiest' : 'map.insight.mostRules')}</h3>
        <ol className="insight-list">
          {topTargets.map(([id, v]) => (
            <li key={id}>
              <button type="button" className="link" onClick={() => { onSelectNode(id); }}>
                <Ltr>{nodeLabel(id)}</Ltr>
              </button>
              <span className="insight-bar" aria-hidden="true">
                <span className={`fill w${String(Math.round((v / max(topTargets)) * 10))}`} />
              </span>
              <span className="insight-value">{v.toLocaleString()}</span>
            </li>
          ))}
        </ol>
      </section>
      <section className="card">
        <h3>{t('map.insight.services')}</h3>
        <ol className="insight-list">
          {topServices.map(([name, v]) => (
            <li key={name}>
              <Ltr>{name}</Ltr>
              <span className="insight-bar" aria-hidden="true">
                <span className={`fill w${String(Math.round((v / max(topServices)) * 10))}`} />
              </span>
              <span className="insight-value">{t('map.insight.connections', { count: v })}</span>
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}
