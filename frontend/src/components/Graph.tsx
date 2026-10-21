import cytoscape from 'cytoscape';
import type {
  Core,
  EdgeSingular,
  ElementDefinition,
  EventObject,
  NodeSingular,
  SingularElementArgument,
  StylesheetJson,
} from 'cytoscape';
import { useEffect, useRef } from 'react';

export type Risk = 'green' | 'yellow' | 'red';

export interface GraphNode {
  id: string;
  label: string;
  tier: string | null;
}

export interface GraphEdge {
  id: string;
  src: string;
  dst: string;
  risk: Risk;
  weight?: number;
}

/** Column order on the canvas: users on the start side, CORE at the end (doctrine flow). */
const COLUMNS = ['USERS', 'ANY', 'BRONZE', 'SILVER', 'GOLD', 'CORE', 'UNCLASSIFIED'] as const;
// Column distance follows the canvas width, so labels stay readable instead of zooming out.
const MAX_COLUMN_GAP = 250;
const MIN_COLUMN_GAP = 135;
const NODE_ALLOWANCE = 150; // room for the widest pill in the outer columns
const FIT_PADDING = 28;
const ROW_GAP = 42;
// Muted, readable risk colours (the focused connection is drawn fully opaque).
export const RISK_COLOURS: Record<Risk, string> = { green: '#4caf7d', yellow: '#e0a336', red: '#e0606b' };
// Tier tints: soft fill + a slightly stronger outline.
const TIER_STYLE = new Map<string, { fill: string; line: string }>([
  ['GOLD', { fill: '#fbf4df', line: '#d6b24c' }],
  ['SILVER', { fill: '#f1f4f7', line: '#9aa7b4' }],
  ['BRONZE', { fill: '#f8ece4', line: '#c08a68' }],
  ['CORE', { fill: '#e9f1fb', line: '#5d8fd0' }],
  ['USERS', { fill: '#f3f0fa', line: '#9c8cc9' }],
]);
const NEUTRAL = { fill: '#f4f5f7', line: '#b7bfc8' };

// Cytoscape prepends an inline <style> (position: relative on its container) unless an
// element with this id exists. Inline styles are blocked by our CSP (style-src 'self');
// the rule lives in styles.css (.graph-canvas), so a placeholder suppresses the injection.
const CYTOSCAPE_STYLESHEET_ID = '__________cytoscape_stylesheet';

function suppressInlineStylesheet(): void {
  if (document.getElementById(CYTOSCAPE_STYLESHEET_ID) !== null) return;
  const placeholder = document.createElement('meta');
  placeholder.id = CYTOSCAPE_STYLESHEET_ID;
  placeholder.name = 'cytoscape-stylesheet';
  placeholder.content = 'provided by styles.css';
  document.head.appendChild(placeholder);
}

function column(node: GraphNode): string {
  if (node.id === 'ANY' || node.id === 'UNCLASSIFIED') return node.id;
  return node.tier ?? 'UNCLASSIFIED';
}

/** Distance between tier columns for a canvas of `width` pixels. */
export function columnGap(width: number, columns: number): number {
  if (columns < 2 || width <= 0) return MAX_COLUMN_GAP;
  const fit = (width - 2 * FIT_PADDING - NODE_ALLOWANCE) / (columns - 1);
  return Math.round(Math.max(MIN_COLUMN_GAP, Math.min(MAX_COLUMN_GAP, fit)));
}

/** Tier columns present in a graph. */
export function columnCount(nodes: GraphNode[]): number {
  return new Set(nodes.map(column)).size;
}

/** Rows in the fullest column (to size the canvas). */
export function maxColumnSize(nodes: GraphNode[]): number {
  const counts = new Map<string, number>();
  for (const n of nodes) counts.set(column(n), (counts.get(column(n)) ?? 0) + 1);
  return Math.max(0, ...counts.values());
}

/** Deterministic layout: one column per tier, systems stacked inside it (RTL mirrors). */
export function elementsFor(
  nodes: GraphNode[],
  edges: GraphEdge[],
  rtl: boolean,
  columnLabel: (column: string) => string = (c) => c,
  gap: number = MAX_COLUMN_GAP,
): ElementDefinition[] {
  const rows = new Map<string, number>();
  const used = COLUMNS.filter((c) => nodes.some((n) => column(n) === c));
  const out: ElementDefinition[] = used.map((c) => ({ data: { id: `col:${c}`, label: columnLabel(c) }, classes: 'column' }));
  for (const node of [...nodes].sort((a, b) => a.label.localeCompare(b.label))) {
    const col = column(node);
    const x = used.indexOf(col as (typeof COLUMNS)[number]) * gap * (rtl ? -1 : 1);
    const row = rows.get(col) ?? 0;
    rows.set(col, row + 1);
    const tint = TIER_STYLE.get(node.tier ?? '') ?? NEUTRAL;
    out.push({
      data: { id: node.id, label: node.label, parent: `col:${col}`, fill: tint.fill, line: tint.line },
      position: { x, y: row * ROW_GAP },
      classes: node.id === 'ANY' || node.id === 'UNCLASSIFIED' ? 'special' : 'system',
    });
  }
  for (const edge of edges) {
    out.push({
      data: {
        id: edge.id,
        source: edge.src,
        target: edge.dst,
        colour: RISK_COLOURS[edge.risk],
        width: 1 + Math.min(3.5, Math.log10((edge.weight ?? 1) + 1) * 1.6),
      },
      classes: `risk-${edge.risk}`,
    });
  }
  return out;
}

const FONT = "'Inter Variable', 'Segoe UI', Arial, sans-serif";

const STYLE: StylesheetJson = [
  {
    selector: 'node.system, node.special',
    style: {
      shape: 'round-rectangle',
      width: 'label',
      height: 26,
      padding: '9px',
      'background-color': 'data(fill)',
      'border-width': 1,
      'border-color': 'data(line)',
      label: 'data(label)',
      'font-family': FONT,
      'font-size': 11,
      'font-weight': 500,
      color: '#24313d',
      'text-valign': 'center',
      'text-halign': 'center',
      'text-max-width': '170px',
      'text-wrap': 'ellipsis',
    },
  },
  { selector: 'node.special', style: { 'border-style': 'dashed', color: '#5f6b77' } },
  {
    selector: 'node.column',
    style: {
      shape: 'round-rectangle',
      'background-color': '#f7f8fa',
      'background-opacity': 0.9,
      'border-width': 0,
      label: 'data(label)',
      'font-family': FONT,
      'font-size': 10,
      'font-weight': 600,
      'text-transform': 'uppercase',
      'text-valign': 'top',
      'text-halign': 'center',
      'text-margin-y': -4,
      color: '#8a96a3',
      padding: '14px',
    },
  },
  {
    selector: 'edge',
    style: {
      width: 'data(width)',
      'line-color': 'data(colour)',
      'target-arrow-color': 'data(colour)',
      'target-arrow-shape': 'triangle',
      'arrow-scale': 0.6,
      'curve-style': 'unbundled-bezier',
      'control-point-distances': [18],
      'control-point-weights': [0.5],
      opacity: 0.42,
    },
  },
  { selector: '.faded', style: { opacity: 0.08 } },
  { selector: 'node.focus', style: { 'border-width': 2, 'z-index': 10 } },
  { selector: 'edge.focus', style: { opacity: 0.95, 'z-index': 10 } },
  { selector: 'node:selected', style: { 'border-width': 2.5, 'border-color': '#1f5fae' } },
  { selector: 'edge:selected', style: { opacity: 1, 'overlay-opacity': 0 } },
];

/** Dim everything except an element and its direct neighbourhood. */
function focus(cy: Core, element: SingularElementArgument | null): void {
  cy.batch(() => {
    cy.elements().removeClass('faded focus');
    if (element === null) return;
    const keep = element.isNode()
      ? element.closedNeighborhood()
      : element.connectedNodes().union(element);
    cy.elements('node.system, node.special, edge').difference(keep).addClass('faded');
    keep.addClass('focus');
  });
}

/** Cytoscape graph (canvas). Events report the selected edge / node id. */
export function Graph({
  nodes,
  edges,
  rtl,
  height,
  label,
  columnLabel,
  onSelectEdge,
  onSelectNode,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  rtl: boolean;
  height?: number;
  label: string;
  columnLabel?: (column: string) => string;
  onSelectEdge?: (id: string) => void;
  onSelectNode?: (id: string) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const pinned = useRef<SingularElementArgument | null>(null);
  const handlers = useRef({ onSelectEdge, onSelectNode });
  // Tall enough for the fullest tier column, within sensible bounds.
  const canvasHeight = height ?? Math.max(380, Math.min(860, maxColumnSize(nodes) * ROW_GAP + 160));

  useEffect(() => {
    handlers.current = { onSelectEdge, onSelectNode };
  }, [onSelectEdge, onSelectNode]);

  useEffect(() => {
    if (container.current === null) return undefined;
    suppressInlineStylesheet();
    const instance = cytoscape({
      container: container.current,
      elements: [],
      style: STYLE,
      layout: { name: 'preset' },
      minZoom: 0.3,
      maxZoom: 1.8,
      autoungrabify: true,
      boxSelectionEnabled: false,
    });
    // Cytoscape types the event target as any; the selectors guarantee its kind.
    instance.on('mouseover', 'node.system, node.special, edge', (event: EventObject) => {
      if (pinned.current === null) focus(instance, event.target as SingularElementArgument);
    });
    instance.on('mouseout', 'node.system, node.special, edge', () => {
      if (pinned.current === null) focus(instance, null);
    });
    instance.on('tap', 'edge', (event: EventObject) => {
      const edge = event.target as EdgeSingular;
      pinned.current = edge;
      focus(instance, edge);
      handlers.current.onSelectEdge?.(edge.id());
    });
    instance.on('tap', 'node.system, node.special', (event: EventObject) => {
      const node = event.target as NodeSingular;
      pinned.current = node;
      focus(instance, node);
      handlers.current.onSelectNode?.(node.id());
    });
    instance.on('tap', (event: EventObject) => {
      if (event.target === instance) {
        pinned.current = null;
        focus(instance, null);
      }
    });
    cy.current = instance;
    return () => {
      instance.destroy();
      cy.current = null;
    };
  }, []);

  useEffect(() => {
    const instance = cy.current;
    if (instance === null) return;
    pinned.current = null;
    instance.elements().remove();
    const gap = columnGap(container.current?.clientWidth ?? 0, columnCount(nodes));
    instance.add(elementsFor(nodes, edges, rtl, columnLabel, gap));
    instance.resize();
    instance.fit(undefined, FIT_PADDING);
  }, [nodes, edges, rtl, columnLabel, canvasHeight]);

  return <div ref={container} className="graph-canvas" style={{ height: canvasHeight }} role="img" aria-label={label} />;
}
