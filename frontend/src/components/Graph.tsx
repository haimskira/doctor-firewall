import cytoscape from 'cytoscape';
import type { Core, EdgeSingular, ElementDefinition, EventObject, NodeSingular, StylesheetJson } from 'cytoscape';
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
const COLUMN_GAP = 230;
const ROW_GAP = 64;
const RISK_COLOURS: Record<Risk, string> = { green: '#2e9e5b', yellow: '#d4a017', red: '#d64545' };
const TIER_COLOURS = new Map<string, string>([
  ['GOLD', '#b8860b'],
  ['SILVER', '#708090'],
  ['BRONZE', '#a0522d'],
  ['CORE', '#1d69cc'],
  ['USERS', '#637282'],
]);

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

/** Deterministic layout: one column per tier, systems stacked inside it (RTL mirrors). */
export function elementsFor(
  nodes: GraphNode[],
  edges: GraphEdge[],
  rtl: boolean,
  columnLabel: (column: string) => string = (c) => c,
): ElementDefinition[] {
  const rows = new Map<string, number>();
  const used = COLUMNS.filter((c) => nodes.some((n) => column(n) === c));
  const out: ElementDefinition[] = used.map((c) => ({ data: { id: `col:${c}`, label: columnLabel(c) }, classes: 'column' }));
  for (const node of [...nodes].sort((a, b) => a.label.localeCompare(b.label))) {
    const col = column(node);
    const x = used.indexOf(col as (typeof COLUMNS)[number]) * COLUMN_GAP * (rtl ? -1 : 1);
    const row = rows.get(col) ?? 0;
    rows.set(col, row + 1);
    out.push({
      data: { id: node.id, label: node.label, parent: `col:${col}`, colour: TIER_COLOURS.get(node.tier ?? '') ?? '#637282' },
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
        width: 1.5 + Math.min(6, Math.log10((edge.weight ?? 1) + 1) * 2),
      },
      classes: `risk-${edge.risk}`,
    });
  }
  return out;
}

const STYLE: StylesheetJson = [
  {
    selector: 'node.system, node.special',
    style: {
      shape: 'round-rectangle',
      width: 150,
      height: 34,
      'background-color': '#ffffff',
      'border-width': 2,
      'border-color': 'data(colour)',
      label: 'data(label)',
      'font-size': 11,
      'text-valign': 'center',
      'text-halign': 'center',
      'text-wrap': 'ellipsis',
      'text-max-width': '140px',
      color: '#1f2a37',
    },
  },
  { selector: 'node.special', style: { 'border-style': 'dashed', 'background-color': '#f2f4f7' } },
  {
    selector: 'node.column',
    style: {
      'background-color': '#eef1f5',
      'background-opacity': 0.6,
      'border-width': 1,
      'border-color': '#d9dee5',
      label: 'data(label)',
      'text-valign': 'top',
      'text-halign': 'center',
      'font-size': 12,
      'font-weight': 'bold',
      color: '#637282',
      padding: '18px',
    },
  },
  {
    selector: 'edge',
    style: {
      width: 'data(width)',
      'line-color': 'data(colour)',
      'target-arrow-color': 'data(colour)',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      opacity: 0.8,
    },
  },
  { selector: ':selected', style: { 'border-width': 4, 'line-style': 'solid', opacity: 1, 'overlay-opacity': 0.12 } },
];

/** Cytoscape graph (canvas). Events report the selected edge / node id. */
export function Graph({
  nodes,
  edges,
  rtl,
  height = 560,
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
  const handlers = useRef({ onSelectEdge, onSelectNode });

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
      minZoom: 0.15,
      maxZoom: 2.5,
      autoungrabify: true,
      boxSelectionEnabled: false,
    });
    // Cytoscape types the event target as any; the selectors guarantee its kind.
    instance.on('tap', 'edge', (event: EventObject) => {
      const edge = event.target as EdgeSingular;
      handlers.current.onSelectEdge?.(edge.id());
    });
    instance.on('tap', 'node.system, node.special', (event: EventObject) => {
      const node = event.target as NodeSingular;
      handlers.current.onSelectNode?.(node.id());
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
    instance.elements().remove();
    instance.add(elementsFor(nodes, edges, rtl, columnLabel));
    instance.fit(undefined, 24);
  }, [nodes, edges, rtl, columnLabel]);

  return <div ref={container} className="graph-canvas" style={{ height }} role="img" aria-label={label} />;
}
