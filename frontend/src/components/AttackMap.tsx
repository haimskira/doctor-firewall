import { useId, useMemo } from 'react';
import type { KeyboardEvent } from 'react';

import type { AttackEdge, AttackNode, AttackSurface } from '../api/types';

/* Radial attack-surface map, drawn in SVG (like the flow view): the target — or, for a blast
   radius, the compromised source — in the centre, one ring per hop away from it. Edges point in
   the direction traffic is allowed, coloured by the worst risk of their rules. Selecting a path
   or a system dims everything else. Text alternative: the ranked path list next to it. */

const NODE_SPACING = 58; // arc length per system on a ring
const RING_GAP = 120;
const FIRST_RING = 130;
const MARGIN = 95; // room for labels outside the last ring
const TIER_ORDER = ['ANY', 'USERS', 'BRONZE', 'UNCLASSIFIED', 'SILVER', 'GOLD', 'CORE'];

interface Point {
  x: number;
  y: number;
}

export interface Highlight {
  nodes: Set<string>;
  edges: Set<string>;
}

export interface Layout {
  points: Map<string, Point>;
  radii: Map<number, number>;
  size: number;
}

function tierOf(n: AttackNode): string {
  if (n.kind === 'anywhere') return 'ANY';
  if (n.kind === 'unclassified') return 'UNCLASSIFIED';
  return n.tier ?? 'UNCLASSIFIED';
}

/** Rings by hop distance; each ring wide enough for its systems, which sit next to the
    systems they connect to on the ring inside it (fewer crossing edges). */
export function layout(nodes: AttackNode[], edges: AttackEdge[]): Layout {
  const byDepth = new Map<number, AttackNode[]>();
  for (const n of nodes) byDepth.set(n.depth, [...(byDepth.get(n.depth) ?? []), n]);
  const depths = [...byDepth.keys()].sort((a, b) => a - b);
  const radii = new Map<number, number>();
  let previous = 0;
  for (const d of depths) {
    const count = byDepth.get(d)?.length ?? 0;
    const needed = (count * NODE_SPACING) / (2 * Math.PI);
    const r = d === 0 ? (count > 1 ? Math.max(46, needed) : 0) : Math.max(previous + RING_GAP, d === 1 ? FIRST_RING : 0, needed);
    radii.set(d, r);
    previous = r;
  }
  const size = 2 * (previous + MARGIN);
  const centre = size / 2;
  const depthOf = new Map(nodes.map((n) => [n.id, n.depth]));
  const neighbours = new Map<string, string[]>();
  for (const e of edges) {
    neighbours.set(e.src, [...(neighbours.get(e.src) ?? []), e.dst]);
    neighbours.set(e.dst, [...(neighbours.get(e.dst) ?? []), e.src]);
  }
  const angles = new Map<string, number>();
  const points = new Map<string, Point>();
  for (const d of depths) {
    const ring = byDepth.get(d) ?? [];
    const inner = (n: AttackNode) =>
      (neighbours.get(n.id) ?? []).flatMap((m) => {
        const a = angles.get(m);
        return depthOf.get(m) === d - 1 && a !== undefined ? [a] : [];
      });
    const keyed = ring.map((n) => {
      const around = inner(n);
      // Mean direction of the inner neighbours (circular mean), else by tier.
      const angle =
        around.length === 0
          ? TIER_ORDER.indexOf(tierOf(n)) / TIER_ORDER.length
          : Math.atan2(
              around.reduce((sum, a) => sum + Math.sin(a), 0),
              around.reduce((sum, a) => sum + Math.cos(a), 0),
            );
      return { n, angle };
    });
    keyed.sort((a, b) => a.angle - b.angle || a.n.label.localeCompare(b.n.label));
    const r = radii.get(d) ?? 0;
    const start = keyed[0]?.angle ?? -Math.PI / 2;
    keyed.forEach(({ n }, i) => {
      const angle = start + (2 * Math.PI * i) / Math.max(1, keyed.length);
      angles.set(n.id, angle);
      points.set(n.id, { x: centre + r * Math.cos(angle), y: centre + r * Math.sin(angle) });
    });
  }
  return { points, radii, size };
}

function nodeRadius(n: AttackNode): number {
  if (n.kind === 'origin') return 24;
  if (n.kind === 'anywhere') return 21;
  return 15;
}

function curve(a: Point, b: Point, ra: number, rb: number): string {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const length = Math.hypot(dx, dy) || 1;
  const ux = dx / length;
  const uy = dy / length;
  // Start / end on the circles' rims, bend sideways so opposite edges do not overlap.
  const start = { x: a.x + ux * ra, y: a.y + uy * ra };
  const end = { x: b.x - ux * (rb + 6), y: b.y - uy * (rb + 6) };
  const bend = Math.min(60, length * 0.18);
  const control = { x: (start.x + end.x) / 2 - uy * bend, y: (start.y + end.y) / 2 + ux * bend };
  return `M ${start.x.toFixed(1)} ${start.y.toFixed(1)} Q ${control.x.toFixed(1)} ${control.y.toFixed(1)} ${end.x.toFixed(1)} ${end.y.toFixed(1)}`;
}

function short(label: string): string {
  return label.length > 20 ? `${label.slice(0, 19)}…` : label;
}

function activate(handler: () => void) {
  return (e: KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      handler();
    }
  };
}

export function AttackMap({
  data,
  highlight,
  label,
  ringLabel,
  onNode,
  onEdge,
}: {
  data: AttackSurface;
  highlight: Highlight | null;
  label: string;
  ringLabel: (depth: number) => string;
  onNode: (node: AttackNode) => void;
  onEdge: (edge: AttackEdge) => void;
}) {
  const uid = useId().replace(/:/g, '');
  const { points, radii, size } = useMemo(() => layout(data.nodes, data.edges), [data.nodes, data.edges]);
  const byId = useMemo(() => new Map(data.nodes.map((n) => [n.id, n])), [data.nodes]);
  const centre = size / 2;
  const rings = [...radii.entries()].filter(([d]) => d > 0);
  const dim = (on: boolean) => (highlight !== null && !on ? ' dim' : '');
  // Edges one ring inwards tell the story; the others only when they are selected.
  const shown = data.edges.filter((e) => {
    const a = byId.get(e.src)?.depth;
    const b = byId.get(e.dst)?.depth;
    return (a !== undefined && b !== undefined && Math.abs(a - b) === 1) || (highlight?.edges.has(e.id) ?? false);
  });

  return (
    <svg className="attack-map" viewBox={`0 0 ${size.toFixed(0)} ${size.toFixed(0)}`} role="img" aria-label={label}>
      <defs>
        {(['green', 'yellow', 'red'] as const).map((risk) => (
          <marker
            key={risk}
            id={`${uid}-arrow-${risk}`}
            viewBox="0 0 10 10"
            refX="8"
            refY="5"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" className={`atk-arrow risk-${risk}`} />
          </marker>
        ))}
      </defs>
      {rings.map(([d, r]) => (
        <g key={d} className="atk-ring">
          <circle cx={centre} cy={centre} r={r} />
          <text x={centre} y={centre - r - 6} textAnchor="middle">
            {ringLabel(d)}
          </text>
        </g>
      ))}
      {shown.map((e) => {
        const a = points.get(e.src);
        const b = points.get(e.dst);
        const na = byId.get(e.src);
        const nb = byId.get(e.dst);
        if (a === undefined || b === undefined || na === undefined || nb === undefined) return null;
        const on = highlight?.edges.has(e.id) ?? true;
        return (
          <path
            key={e.id}
            className={`atk-edge risk-${e.risk}${dim(on)}${highlight !== null && on ? ' on' : ''}`}
            d={curve(a, b, nodeRadius(na), nodeRadius(nb))}
            markerEnd={`url(#${uid}-arrow-${e.risk})`}
            role="button"
            tabIndex={0}
            aria-label={`${na.label} → ${nb.label}: ${e.services.join(', ')}`}
            onClick={() => {
              onEdge(e);
            }}
            onKeyDown={activate(() => {
              onEdge(e);
            })}
          >
            <title>{`${na.label} → ${nb.label}\n${e.services.join(', ')}`}</title>
          </path>
        );
      })}
      {data.nodes.map((n) => {
        const p = points.get(n.id);
        if (p === undefined) return null;
        const on = highlight?.nodes.has(n.id) ?? true;
        const r = nodeRadius(n);
        return (
          <g
            key={n.id}
            className={`atk-node kind-${n.kind} tier-${tierOf(n).toLowerCase()}${dim(on)}`}
            transform={`translate(${p.x.toFixed(1)} ${p.y.toFixed(1)})`}
            role="button"
            tabIndex={0}
            aria-label={n.label}
            onClick={() => {
              onNode(n);
            }}
            onKeyDown={activate(() => {
              onNode(n);
            })}
          >
            <title>{[n.label, ...n.networks].join('\n')}</title>
            {n.kind === 'origin' && <circle className="atk-halo" r={r + 7} />}
            <circle r={r} />
            <text y={r + 14} textAnchor="middle">
              {short(n.label)}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
