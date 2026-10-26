import cytoscape from 'cytoscape';
import type { Core, ElementDefinition, EventObject, NodeSingular, StylesheetJson } from 'cytoscape';
import { useEffect, useRef } from 'react';

import type { ObjectRelations } from '../api/types';
import { readPalette, RISK_COLOURS, useThemeVersion } from './Graph';
import type { Palette } from './Graph';

const COL = 210;
const ROW = 46;
const CYTOSCAPE_STYLESHEET_ID = '__________cytoscape_stylesheet';
const MAX_LABEL = 28;

function shown(label: string): string {
  return label.length > MAX_LABEL ? `${label.slice(0, MAX_LABEL - 1)}…` : label;
}

/** Approximate rendered width of an 11px label plus padding. */
export function nodeWidth(label: string): number {
  return Math.round(Math.max(48, label.length * 6.8 + 22));
}

/**
 * Layered layout: members of the object on one side, the object in the middle, the chain of
 * groups containing it level by level, then the rules using any of those levels; objects that
 * overlap its addresses sit under it. Redundant links (a rule / group reaching the same object
 * twice) are drawn in red.
 */
export function relationElements(rel: ObjectRelations, rtl: boolean): ElementDefinition[] {
  const columns = new Map<number, number>();
  const ruleDepth = Math.max(1, ...rel.nodes.filter((n) => n.role !== 'rule').map((n) => n.depth)) + 1;
  const columnOf = (n: ObjectRelations['nodes'][number]) => (n.role === 'rule' ? ruleDepth : n.depth);
  const overlapRow = new Map<string, number>();
  const ordered = [...rel.nodes].sort((a, b) => a.label.localeCompare(b.label));
  const out: ElementDefinition[] = [];
  const selfRows = 1;
  let overlaps = 0;
  for (const n of ordered) {
    let x: number;
    let y: number;
    if (n.role === 'overlap') {
      overlapRow.set(n.id, overlaps);
      x = 0;
      y = (selfRows + 1 + overlaps) * ROW;
      overlaps += 1;
    } else {
      const col = columnOf(n);
      const row = columns.get(col) ?? 0;
      columns.set(col, row + 1);
      x = col * COL;
      y = n.role === 'self' ? 0 : row * ROW;
    }
    out.push({
      // Width from the label, not cytoscape's "label" sizing: that is measured once and cached,
      // so a label measured before the font is ready would leave the node at width 0 (hidden).
      data: { id: n.id, label: shown(n.label), detail: n.detail, w: nodeWidth(shown(n.label)) },
      position: { x: rtl ? -x : x, y },
      classes: `rel-${n.role} kind-${n.kind}`,
    });
  }
  const byLabel = new Map(rel.nodes.map((n) => [n.label, n.id]));
  const redundant = new Set<string>();
  for (const issue of rel.issues) {
    const removed = byLabel.get(issue.removed);
    if (removed === undefined) continue;
    redundant.add(issue.kind === 'redundant_reference' ? `${removed}->rule:${issue.where_id}` : `${removed}->${issue.where_id}`);
  }
  rel.edges.forEach((e, i) => {
    out.push({
      data: { id: `e${String(i)}`, source: e.source, target: e.target, label: e.label },
      classes: `rel-${e.kind}${redundant.has(`${e.source}->${e.target}`) ? ' redundant' : ''}`,
    });
  });
  return out;
}

export function styleFor(p: Palette): StylesheetJson {
  const font = "'Inter Variable', 'Segoe UI', Arial, sans-serif";
  return [
    {
      selector: 'node',
      style: {
        shape: 'round-rectangle',
        width: 'data(w)',
        height: 26,
        label: 'data(label)',
        'font-family': font,
        'font-size': 11,
        color: p.text,
        'text-valign': 'center',
        'text-halign': 'center',
        'background-color': p.surface,
        'border-width': 1,
        'border-color': p.border,
      },
    },
    { selector: 'node.rel-self', style: { 'border-width': 2.5, 'border-color': p.primary, 'font-weight': 700 } },
    { selector: 'node.rel-ancestor', style: { 'border-color': p.tiers.get('GOLD') ?? p.border } },
    { selector: 'node.rel-descendant', style: { 'border-color': p.tiers.get('SILVER') ?? p.border } },
    { selector: 'node.rel-rule', style: { shape: 'rectangle', 'border-color': p.primary, 'background-color': p.band } },
    { selector: 'node.rel-overlap', style: { 'border-style': 'dashed', color: p.muted } },
    {
      selector: 'edge',
      style: {
        width: 1.3,
        'curve-style': 'bezier',
        'line-color': p.border,
        'target-arrow-color': p.border,
        'target-arrow-shape': 'triangle',
        'arrow-scale': 0.7,
        opacity: 0.75,
      },
    },
    { selector: 'edge.rel-uses', style: { 'line-color': p.primary, 'target-arrow-color': p.primary } },
    {
      selector: 'edge.rel-overlap',
      style: {
        'line-style': 'dashed',
        'target-arrow-shape': 'none',
        label: 'data(label)',
        'font-size': 9,
        color: p.muted,
        'text-background-color': p.surface,
        'text-background-opacity': 1,
      },
    },
    {
      selector: 'edge.redundant',
      style: {
        'line-color': RISK_COLOURS.red,
        'target-arrow-color': RISK_COLOURS.red,
        width: 2.4,
        opacity: 1,
        'line-style': 'dashed',
      },
    },
    { selector: '.faded', style: { opacity: 0.12 } },
  ];
}

export function RelationsMap({
  relations,
  rtl,
  label,
  onOpenObject,
}: {
  relations: ObjectRelations;
  rtl: boolean;
  label: string;
  onOpenObject: (id: string) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const open = useRef(onOpenObject);
  const theme = useThemeVersion();
  const perColumn = new Map<string, number>();
  for (const n of relations.nodes) {
    const key = n.role === 'rule' ? 'rule' : n.role === 'overlap' ? 'overlap' : String(n.depth);
    perColumn.set(key, (perColumn.get(key) ?? 0) + 1);
  }
  const rows = Math.max(3, ...perColumn.values());
  const height = Math.max(320, Math.min(820, rows * ROW + 120));

  useEffect(() => {
    open.current = onOpenObject;
  }, [onOpenObject]);

  useEffect(() => {
    if (container.current === null) return undefined;
    if (document.getElementById(CYTOSCAPE_STYLESHEET_ID) === null) {
      const placeholder = document.createElement('meta');
      placeholder.id = CYTOSCAPE_STYLESHEET_ID;
      placeholder.name = 'cytoscape-stylesheet';
      placeholder.content = 'provided by styles.css';
      document.head.appendChild(placeholder);
    }
    const instance = cytoscape({
      container: container.current,
      elements: [],
      layout: { name: 'preset' },
      minZoom: 0.25,
      maxZoom: 1.8,
      autoungrabify: true,
      boxSelectionEnabled: false,
    });
    instance.on('mouseover', 'node', (event: EventObject) => {
      const node = event.target as NodeSingular;
      instance.batch(() => {
        instance.elements().addClass('faded');
        node.closedNeighborhood().removeClass('faded');
      });
    });
    instance.on('mouseout', 'node', () => {
      instance.elements().removeClass('faded');
    });
    instance.on('tap', 'node', (event: EventObject) => {
      const node = event.target as NodeSingular;
      if (!node.hasClass('rel-rule') && !node.hasClass('rel-self')) open.current(node.id());
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
    instance.style(styleFor(readPalette()));
    instance.add(relationElements(relations, rtl));
    instance.resize();
    instance.fit(undefined, 30);
  }, [relations, rtl, theme, height]);

  return <div ref={container} className="graph-canvas" style={{ height }} role="img" aria-label={label} />;
}
