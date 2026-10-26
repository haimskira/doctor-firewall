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
import { useEffect, useRef, useState } from 'react';

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
/** Colours of the current theme (CSS custom properties; light defaults outside a browser). */
export interface Palette {
  text: string;
  muted: string;
  surface: string;
  band: string;
  border: string;
  primary: string;
  tiers: Map<string, string>;
}

const LIGHT: Palette = {
  text: '#24313d',
  muted: '#5f6b77',
  surface: '#ffffff',
  band: '#f4f5f7',
  border: '#b7bfc8',
  primary: '#1f5fae',
  tiers: new Map([
    ['GOLD', '#b8860b'],
    ['SILVER', '#708090'],
    ['BRONZE', '#a0522d'],
    ['CORE', '#1f5fae'],
    ['USERS', '#7a4fc4'],
  ]),
};

export function readPalette(): Palette {
  const css = getComputedStyle(document.documentElement);
  const read = (name: string, fallback: string) => css.getPropertyValue(name).trim() || fallback;
  return {
    text: read('--text', LIGHT.text),
    muted: read('--muted', LIGHT.muted),
    surface: read('--surface', LIGHT.surface),
    band: read('--band', LIGHT.band),
    border: read('--border-strong', LIGHT.border),
    primary: read('--primary', LIGHT.primary),
    tiers: new Map([
      ['GOLD', read('--tier-gold', '#b8860b')],
      ['SILVER', read('--tier-silver', '#708090')],
      ['BRONZE', read('--tier-bronze', '#a0522d')],
      ['CORE', read('--primary', '#1f5fae')],
      ['USERS', read('--inspect', '#7a4fc4')],
    ]),
  };
}

/** Re-render key that changes when the theme (user choice or OS setting) changes. */
export function useThemeVersion(): number {
  const [version, setVersion] = useState(0);
  useEffect(() => {
    const bump = () => {
      setVersion((v) => v + 1);
    };
    const observer = new MutationObserver(bump);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    const media = typeof window.matchMedia === 'function' ? window.matchMedia('(prefers-color-scheme: dark)') : null;
    media?.addEventListener('change', bump);
    return () => {
      observer.disconnect();
      media?.removeEventListener('change', bump);
    };
  }, []);
  return version;
}

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

function short(label: string): string {
  return label.length > 26 ? `${label.slice(0, 25)}…` : label;
}

/** Approximate rendered width of an 11px label plus padding. */
export function labelWidth(label: string): number {
  return Math.round(Math.max(44, label.length * 6.8 + 22));
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
  palette: Palette = LIGHT,
): ElementDefinition[] {
  const rows = new Map<string, number>();
  const used = COLUMNS.filter((c) => nodes.some((n) => column(n) === c));
  const out: ElementDefinition[] = used.map((c) => ({ data: { id: `col:${c}`, label: columnLabel(c) }, classes: 'column' }));
  for (const node of [...nodes].sort((a, b) => a.label.localeCompare(b.label))) {
    const col = column(node);
    const x = used.indexOf(col as (typeof COLUMNS)[number]) * gap * (rtl ? -1 : 1);
    const row = rows.get(col) ?? 0;
    rows.set(col, row + 1);
    const line = palette.tiers.get(node.tier ?? '') ?? palette.border;
    out.push({
      // Explicit width: cytoscape caches "label" sizing, and a label measured before the font is
      // ready would leave the node at width 0 (never drawn).
      data: { id: node.id, label: short(node.label), parent: `col:${col}`, fill: palette.surface, line, w: labelWidth(short(node.label)) },
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

function styleFor(p: Palette): StylesheetJson {
  return [
  {
    selector: 'node.system, node.special',
    style: {
      shape: 'round-rectangle',
      width: 'data(w)',
      height: 26,
      'background-color': 'data(fill)',
      'border-width': 1,
      'border-color': 'data(line)',
      label: 'data(label)',
      'font-family': FONT,
      'font-size': 11,
      'font-weight': 500,
      color: p.text,
      'text-valign': 'center',
      'text-halign': 'center',
    },
  },
  { selector: 'node.special', style: { 'border-style': 'dashed', color: p.muted } },
  {
    selector: 'node.column',
    style: {
      shape: 'round-rectangle',
      'background-color': p.band,
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
      color: p.muted,
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
  { selector: 'node:selected', style: { 'border-width': 2.5, 'border-color': p.primary } },
  { selector: 'edge:selected', style: { opacity: 1, 'overlay-opacity': 0 } },
  ];
}

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
  const theme = useThemeVersion();
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
      style: styleFor(LIGHT),
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
    const palette = readPalette();
    instance.style(styleFor(palette));
    const gap = columnGap(container.current?.clientWidth ?? 0, columnCount(nodes));
    instance.add(elementsFor(nodes, edges, rtl, columnLabel, gap, palette));
    instance.resize();
    instance.fit(undefined, FIT_PADDING);
  }, [nodes, edges, rtl, columnLabel, canvasHeight, theme]);

  return <div ref={container} className="graph-canvas" style={{ height: canvasHeight }} role="img" aria-label={label} />;
}
