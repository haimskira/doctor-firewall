import { useCallback, useMemo } from 'react';

import type { MapChangeEdge, MapRisk } from '../api/types';
import { isMessageKey, useI18n } from '../i18n/I18nProvider';
import { Ltr } from './common';
import { Graph } from './Graph';

/** Node label: systems by name; the two special nodes (ANY / UNCLASSIFIED) translated. */
export function useNodeLabel(): (id: string, fallback?: string) => string {
  const { t } = useI18n();
  return useCallback(
    (id: string, fallback?: string) => {
      const key = `map.node.${id}`;
      if (isMessageKey(key)) return t(key);
      return fallback ?? (id.includes('|') ? id.slice(id.indexOf('|') + 1) : id);
    },
    [t],
  );
}

/** A doctrine reason code as short text (placeholders of the score texts dropped). */
export function useReasonLabel(): (code: string) => string {
  const { t } = useI18n();
  return useCallback(
    (code: string) => {
      const key = `score.reason.${code}`;
      if (!isMessageKey(key)) return code;
      return t(key)
        .replace(/\s*\([^)]*\{\w+\}[^)]*\)/g, '')
        .replace(/\{\w+\}/g, '…');
    },
    [t],
  );
}

export function RiskBadge({ risk }: { risk: MapRisk }) {
  const { t } = useI18n();
  return <span className={`badge risk-badge risk-${risk}`}>{t(`map.risk.${risk}`)}</span>;
}

function tierOf(id: string): string | null {
  return id.includes('|') ? id.slice(0, id.indexOf('|')) : null;
}

function ChangeSide({ title, edges }: { title: string; edges: MapChangeEdge[] }) {
  const { t, dir } = useI18n();
  const nodeLabel = useNodeLabel();
  const nodes = useMemo(() => {
    const ids = [...new Set(edges.flatMap((e) => [e.src, e.dst]))];
    return ids.map((id) => ({ id, label: nodeLabel(id), tier: tierOf(id) }));
  }, [edges, nodeLabel]);
  const graphEdges = useMemo(
    () => edges.map((e) => ({ id: `${e.src}->${e.dst}`, src: e.src, dst: e.dst, risk: e.risk })),
    [edges],
  );
  return (
    <div>
      <h3>{title}</h3>
      {edges.length === 0 ? (
        <p className="muted small">{t('map.noTraffic')}</p>
      ) : (
        <>
          <Graph nodes={nodes} edges={graphEdges} rtl={dir === 'rtl'} height={220} label={`${t('map.change')}: ${title}`} />
          <ul className="plain-list small">
            {edges.map((e) => (
              <li key={`${e.src}->${e.dst}`}>
                <span className={`swatch-dot risk-${e.risk}`} aria-hidden="true" /> <Ltr>{nodeLabel(e.src)}</Ltr> →{' '}
                <Ltr>{nodeLabel(e.dst)}</Ltr>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

/** The map before and after a recommendation (the spec's before / after view). */
export function MapChange({ before, after }: { before: MapChangeEdge[]; after: MapChangeEdge[] }) {
  const { t } = useI18n();
  return (
    <section>
      <h3>{t('map.change')}</h3>
      <div className="split-view">
        <ChangeSide title={t('rec.before')} edges={before} />
        <ChangeSide title={t('rec.after')} edges={after} />
      </div>
    </section>
  );
}
