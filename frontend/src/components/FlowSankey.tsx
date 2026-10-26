import { useEffect, useMemo, useRef, useState } from 'react';
import type { RefObject } from 'react';

import type { MapRisk } from '../api/types';

/** One connection as the flow view needs it. */
export interface FlowEdge {
  id: string;
  src: string;
  dst: string;
  ruleCount: number;
  hits: number;
  riskRules: Partial<Record<MapRisk, number>>;
  riskHits: Partial<Record<MapRisk, number>>;
  fallbackRisk: MapRisk;
}

export interface FlowNode {
  id: string;
  label: string;
  tier: string | null;
}

export type FlowMetric = 'rules' | 'hits';

const RISK_ORDER: readonly MapRisk[] = ['red', 'yellow', 'green'];
const TIER_ORDER = ['CORE', 'GOLD', 'SILVER', 'BRONZE', 'USERS', 'ANY', 'UNCLASSIFIED'];
const NODE_W = 12;
const GAP = 8;
const MAX_PER_SIDE = 16;
const MIN_BAND = 1.5;
const MIN_NODE = 16;
const LABEL_SPACE = 190;
export const OTHER = '__other__';

interface Side {
  key: string; // "s:<id>" / "d:<id>"
  id: string;
  label: string;
  tier: string | null;
  value: number;
  y: number;
  h: number;
  cursor: number; // next free y for a band
}

interface Band {
  edge: string; // edge id (or OTHER)
  risk: MapRisk;
  value: number;
  path: string;
  src: string;
  dst: string;
}

function tierRank(tier: string | null): number {
  const i = TIER_ORDER.indexOf(tier ?? 'UNCLASSIFIED');
  return i < 0 ? TIER_ORDER.length : i;
}

/** Value of a connection per risk colour for the chosen metric (falls back to its worst risk). */
export function riskParts(edge: FlowEdge, metric: FlowMetric): [MapRisk, number][] {
  const source = metric === 'hits' ? edge.riskHits : edge.riskRules;
  const total = metric === 'hits' ? edge.hits : edge.ruleCount;
  const entries = new Map(Object.entries(source));
  const parts = RISK_ORDER.map((r): [MapRisk, number] => [r, entries.get(r) ?? 0]).filter(([, v]) => v > 0);
  if (parts.length > 0) return parts;
  return total > 0 ? [[edge.fallbackRisk, total]] : [];
}

function ribbon(x0: number, y0: number, x1: number, y1: number, h: number): string {
  const mid = (x0 + x1) / 2;
  return [
    `M${x0.toFixed(1)},${y0.toFixed(1)}`,
    `C${mid.toFixed(1)},${y0.toFixed(1)} ${mid.toFixed(1)},${y1.toFixed(1)} ${x1.toFixed(1)},${y1.toFixed(1)}`,
    `L${x1.toFixed(1)},${(y1 + h).toFixed(1)}`,
    `C${mid.toFixed(1)},${(y1 + h).toFixed(1)} ${mid.toFixed(1)},${(y0 + h).toFixed(1)} ${x0.toFixed(1)},${(y0 + h).toFixed(1)}`,
    'Z',
  ].join(' ');
}

/**
 * Pure layout (tested separately): sources in one column, destinations in the other, every
 * connection split into bands by risk; the smallest nodes of a side are folded into "others".
 */
export function layoutFlows(
  nodes: FlowNode[],
  edges: FlowEdge[],
  metric: FlowMetric,
  width: number,
  height: number,
  rtl: boolean,
  otherLabel: (count: number) => string,
): { sources: Side[]; targets: Side[]; bands: Band[]; folded: { sources: number; targets: number } } {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const weight = (e: FlowEdge) => riskParts(e, metric).reduce((sum, [, v]) => sum + v, 0);
  const totals = (pick: (e: FlowEdge) => string) => {
    const m = new Map<string, number>();
    for (const e of edges) m.set(pick(e), (m.get(pick(e)) ?? 0) + weight(e));
    return m;
  };
  const keep = (m: Map<string, number>) =>
    new Set([...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, MAX_PER_SIDE).map(([id]) => id));
  const srcTotals = totals((e) => e.src);
  const dstTotals = totals((e) => e.dst);
  const keepSrc = keep(srcTotals);
  const keepDst = keep(dstTotals);
  const fold = (id: string, kept: Set<string>) => (kept.has(id) ? id : OTHER);

  // Aggregate after folding: (src, dst, risk) -> value, remembering a representative edge id.
  const flows = new Map<string, { src: string; dst: string; risk: MapRisk; value: number; edge: string }>();
  for (const e of edges) {
    const s = fold(e.src, keepSrc);
    const d = fold(e.dst, keepDst);
    for (const [risk, value] of riskParts(e, metric)) {
      const key = `${s}\u0000${d}\u0000${risk}`;
      const cur = flows.get(key);
      if (cur === undefined) flows.set(key, { src: s, dst: d, risk, value, edge: s === OTHER || d === OTHER ? OTHER : e.id });
      else cur.value += value;
    }
  }

  const makeSides = (prefix: string, ids: string[], folded: number): Side[] =>
    ids.map((id) => {
      const node = byId.get(id);
      return {
        key: `${prefix}:${id}`,
        id,
        label: id === OTHER ? otherLabel(folded) : (node?.label ?? id),
        tier: id === OTHER ? null : (node?.tier ?? null),
        value: 0,
        y: 0,
        h: 0,
        cursor: 0,
      };
    });
  const flowList = [...flows.values()];
  const value = (side: 's' | 'd', id: string) =>
    flowList.filter((f) => (side === 's' ? f.src : f.dst) === id).reduce((sum, f) => sum + f.value, 0);
  const dstIds = [...new Set(flowList.map((f) => f.dst))].sort(
    (a, b) => tierRank(byId.get(a)?.tier ?? null) - tierRank(byId.get(b)?.tier ?? null) || value('d', b) - value('d', a),
  );
  if (dstIds.includes(OTHER)) dstIds.push(...dstIds.splice(dstIds.indexOf(OTHER), 1));
  const targets = makeSides('d', dstIds, dstTotals.size - keepDst.size);
  const dstIndex = new Map(dstIds.map((id, i) => [id, i]));
  // Sources ordered by the weighted position of their destinations: fewer crossings.
  const srcIds = [...new Set(flowList.map((f) => f.src))];
  const center = new Map(
    srcIds.map((id) => {
      const mine = flowList.filter((f) => f.src === id);
      const total = mine.reduce((sum, f) => sum + f.value, 0) || 1;
      return [id, mine.reduce((sum, f) => sum + (dstIndex.get(f.dst) ?? 0) * f.value, 0) / total];
    }),
  );
  srcIds.sort((a, b) => (a === OTHER ? 1 : b === OTHER ? -1 : (center.get(a) ?? 0) - (center.get(b) ?? 0)));
  const sources = makeSides('s', srcIds, srcTotals.size - keepSrc.size);

  for (const s of sources) s.value = value('s', s.id);
  for (const d of targets) d.value = value('d', d.id);
  const place = (sides: Side[]) => {
    const total = sides.reduce((sum, s) => sum + s.value, 0) || 1;
    const usable = Math.max(40, height - GAP * Math.max(0, sides.length - 1));
    // Every node keeps room for its label; the rest is shared by value.
    const floor = Math.min(MIN_NODE, usable / Math.max(1, sides.length));
    const spare = Math.max(0, usable - floor * sides.length);
    let y = 0;
    for (const s of sides) {
      s.h = floor + (s.value / total) * spare;
      s.y = y;
      s.cursor = y;
      y += s.h + GAP;
    }
  };
  place(sources);
  place(targets);

  const left = LABEL_SPACE;
  const right = width - LABEL_SPACE - NODE_W;
  const xSrc = rtl ? right : left;
  const xDst = rtl ? left : right;
  const srcMap = new Map(sources.map((s) => [s.id, s]));
  const dstMap = new Map(targets.map((d) => [d.id, d]));
  const bands: Band[] = [];
  const ordered = flowList.sort(
    (a, b) =>
      (dstIndex.get(a.dst) ?? 0) - (dstIndex.get(b.dst) ?? 0) ||
      RISK_ORDER.indexOf(a.risk) - RISK_ORDER.indexOf(b.risk),
  );
  for (const f of ordered) {
    const s = srcMap.get(f.src);
    const d = dstMap.get(f.dst);
    if (s === undefined || d === undefined) continue;
    const hs = Math.max(MIN_BAND, (f.value / (s.value || 1)) * s.h);
    const hd = Math.max(MIN_BAND, (f.value / (d.value || 1)) * d.h);
    const h = Math.min(hs, hd);
    const x0 = rtl ? xSrc : xSrc + NODE_W;
    const x1 = rtl ? xDst + NODE_W : xDst;
    bands.push({ edge: f.edge, risk: f.risk, value: f.value, src: s.id, dst: d.id, path: ribbon(x0, s.cursor, x1, d.cursor, h) });
    s.cursor += hs;
    d.cursor += hd;
  }
  return { sources, targets, bands, folded: { sources: srcTotals.size - keepSrc.size, targets: dstTotals.size - keepDst.size } };
}

function useWidth(ref: RefObject<HTMLDivElement | null>): number {
  const [width, setWidth] = useState(960);
  useEffect(() => {
    const el = ref.current;
    if (el === null) return undefined;
    setWidth(el.clientWidth || 960);
    if (typeof ResizeObserver !== 'function') return undefined;
    const observer = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width;
      if (w !== undefined && w > 0) setWidth(w);
    });
    observer.observe(el);
    return () => {
      observer.disconnect();
    };
  }, [ref]);
  return width;
}

/** Flow (Sankey) view of the connectivity map. */
export function FlowSankey({
  nodes,
  edges,
  metric,
  rtl,
  label,
  selected,
  otherLabel,
  describe,
  onSelectEdge,
  onSelectNode,
}: {
  nodes: FlowNode[];
  edges: FlowEdge[];
  metric: FlowMetric;
  rtl: boolean;
  label: string;
  selected: string | null;
  otherLabel: (count: number) => string;
  describe: (band: { src: string; dst: string; risk: MapRisk; value: number }) => string;
  onSelectEdge: (id: string) => void;
  onSelectNode: (id: string) => void;
}) {
  const box = useRef<HTMLDivElement>(null);
  const width = Math.max(560, useWidth(box));
  const [hover, setHover] = useState<{ kind: 'node' | 'band'; id: string } | null>(null);
  const rows = Math.max(
    new Set(edges.map((e) => e.src)).size,
    new Set(edges.map((e) => e.dst)).size,
  );
  const height = Math.max(320, Math.min(760, Math.min(rows, MAX_PER_SIDE + 1) * 34 + 40));
  const layout = useMemo(
    () => layoutFlows(nodes, edges, metric, width, height, rtl, otherLabel),
    [nodes, edges, metric, width, height, rtl, otherLabel],
  );

  const active = (b: Band, i: number): boolean => {
    if (hover === null) return selected === null || b.edge === selected;
    if (hover.kind === 'band') return hover.id === String(i);
    return b.src === hover.id || b.dst === hover.id;
  };
  const left = LABEL_SPACE;
  const right = width - LABEL_SPACE - NODE_W;
  const column = (side: 's' | 'd') => ((side === 's') !== rtl ? left : right);

  return (
    <div ref={box} className="flow-box">
      {/* Physical geometry: mirroring for RTL is done by the layout, not by SVG text direction. */}
      <svg className="flow" direction="ltr" width={width} height={height + 8} role="img" aria-label={label}>
        <g transform="translate(0,4)">
          {layout.bands.map((b, i) => (
            <path
              key={`${b.src}-${b.dst}-${b.risk}`}
              d={b.path}
              className={`flow-band risk-${b.risk}${active(b, i) ? ' on' : ' off'}`}
              onMouseEnter={() => {
                setHover({ kind: 'band', id: String(i) });
              }}
              onMouseLeave={() => {
                setHover(null);
              }}
              onClick={() => {
                if (b.edge !== OTHER) onSelectEdge(b.edge);
              }}
            >
              <title>{describe(b)}</title>
            </path>
          ))}
          {(['s', 'd'] as const).map((side) =>
            (side === 's' ? layout.sources : layout.targets).map((n) => {
              const x = column(side);
              const outer = x === left; // labels sit on the outer edge of the canvas
              const tier = (n.tier ?? 'none').toLowerCase();
              return (
                <g
                  key={n.key}
                  className={`flow-node tier-${tier}${n.id === OTHER ? ' other' : ''}`}
                  onMouseEnter={() => {
                    setHover({ kind: 'node', id: n.id });
                  }}
                  onMouseLeave={() => {
                    setHover(null);
                  }}
                  onClick={() => {
                    if (n.id !== OTHER) onSelectNode(n.id);
                  }}
                >
                  <rect x={x} y={n.y} width={NODE_W} height={n.h} rx={3} />
                  <text
                    x={outer ? x - 8 : x + NODE_W + 8}
                    y={n.y + n.h / 2}
                    dominantBaseline="middle"
                    textAnchor={outer ? 'end' : 'start'}
                  >
                    {n.label.length > 26 ? `${n.label.slice(0, 25)}…` : n.label}
                  </text>
                  <title>{`${n.label} · ${n.value.toLocaleString()}`}</title>
                </g>
              );
            }),
          )}
        </g>
      </svg>
    </div>
  );
}
