import type { KeyboardEvent } from 'react';

import type { Dossier, DossierPeer } from '../api/types';

export type Side = 'inbound' | 'outbound';

export interface DiagramLabels {
  inbound: string;
  outbound: string;
  peerName: (peer: DossierPeer) => string;
  peerSub: (peer: DossierPeer) => string;
  more: (count: number) => string;
}

interface Props {
  dossier: Dossier;
  inbound: DossierPeer[];
  outbound: DossierPeer[];
  selected: { side: Side; key: string } | null;
  onSelect: (side: Side, key: string) => void;
  rtl: boolean;
  labels: DiagramLabels;
}

const W = 1200;
const COL_W = 270;
const NODE_H = 56;
const GAP = 14;
const CENTER_W = 320;
const HEAD = 46;
const LINE = 19;
const MAX_LINES = 12;
const SERVICES_SHOWN = 2;

function cut(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function serviceText(peer: DossierPeer, more: (n: number) => string): string {
  const names = [...peer.services, ...peer.apps];
  const shown = names.slice(0, SERVICES_SHOWN).join(' · ');
  return names.length > SERVICES_SHOWN ? `${shown} ${more(names.length - SERVICES_SHOWN)}` : shown;
}

function nodeClass(peer: DossierPeer): string {
  const tier = peer.tier === null ? '' : ` tier-${peer.tier.toLowerCase()}`;
  return `dsr-node kind-${peer.kind}${tier}`;
}

/**
 * The system in the centre, who reaches it on one side and what it reaches on the other.
 * Reading direction decides the sides: inbound on the reading start, outbound on the end.
 */
export function DossierDiagram({ dossier, inbound, outbound, selected, onSelect, rtl, labels }: Props) {
  const rows = Math.max(inbound.length, outbound.length, 1);
  const columnH = rows * (NODE_H + GAP) - GAP;
  const components = dossier.system.components.slice(0, MAX_LINES);
  const extraComponents = dossier.system.components.length - components.length;
  const textH = 76 + (components.length + (extraComponents > 0 ? 1 : 0)) * LINE;
  const centerH = Math.max(110, textH, Math.min(columnH * 0.55, 640));
  const bodyH = Math.max(columnH, centerH);
  const H = HEAD + bodyH + 24;
  const startX = rtl ? W - COL_W - 8 : 8; // reading start: inbound
  const endX = rtl ? 8 : W - COL_W - 8; // reading end: outbound
  const centerX = (W - CENTER_W) / 2;
  const centerY = HEAD + (bodyH - centerH) / 2;
  const textY = centerY + (centerH - textH) / 2; // the centre's text block, vertically centred

  function column(side: Side, peers: DossierPeer[]) {
    const x = side === 'inbound' ? startX : endX;
    const top = HEAD + (bodyH - (peers.length * (NODE_H + GAP) - GAP)) / 2;
    // The side of a peer box that faces the centre, and the centre box side that faces it.
    const towardsCentre = (side === 'inbound') !== rtl;
    const peerEdge = towardsCentre ? x + COL_W : x;
    const centreEdge = towardsCentre ? centerX : centerX + CENTER_W;
    const span = centerH - 36;
    return peers.map((peer, i) => {
      const y = top + i * (NODE_H + GAP);
      const py = y + NODE_H / 2;
      const cy = centerY + 18 + ((i + 0.5) * span) / Math.max(peers.length, 1);
      const mid = (peerEdge + centreEdge) / 2;
      const [x1, y1, x2, y2] = side === 'inbound' ? [peerEdge, py, centreEdge, cy] : [centreEdge, cy, peerEdge, py];
      const isSelected = selected?.side === side && selected.key === peer.key;
      const dim = selected !== null && !isSelected;
      const labelX = peerEdge + (towardsCentre ? 10 : -10);
      const onKey = (e: KeyboardEvent<SVGGElement>) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect(side, peer.key);
        }
      };
      const name = labels.peerName(peer);
      const sub = labels.peerSub(peer);
      return (
        <g key={`${side}:${peer.key}`} className={`dsr-peer${isSelected ? ' selected' : ''}${dim ? ' dim' : ''}`}>
          <path
            className={`dsr-edge risk-${peer.risk}${peer.specific === 0 ? ' broad' : ''}`}
            d={`M${String(x1)} ${String(y1)} C${String(mid)} ${String(y1)}, ${String(mid)} ${String(y2)}, ${String(x2)} ${String(y2)}`}
            markerEnd={`url(#dsr-arrow-${peer.risk})`}
          />
          <text
            className="dsr-service"
            x={labelX}
            y={py - 7}
            textAnchor={towardsCentre ? 'start' : 'end'}
            direction="ltr"
          >
            {serviceText(peer, labels.more)}
          </text>
          <g
            role="button"
            tabIndex={0}
            aria-pressed={isSelected}
            aria-label={`${side === 'inbound' ? labels.inbound : labels.outbound}: ${name}`}
            className={nodeClass(peer)}
            onClick={() => {
              onSelect(side, peer.key);
            }}
            onKeyDown={onKey}
          >
            <title>{`${name}\n${peer.values.join(', ')}\n${[...peer.services, ...peer.apps].join(', ')}`}</title>
            <rect x={x} y={y} width={COL_W} height={NODE_H} rx={8} />
            <rect className="dsr-stripe" x={rtl ? x + COL_W - 5 : x} y={y} width={5} height={NODE_H} rx={2} />
            <text className="dsr-name" x={rtl ? x + COL_W - 16 : x + 16} y={y + 23} textAnchor="start" direction={rtl ? 'rtl' : 'ltr'}>
              {cut(name, 30)}
            </text>
            <text className="dsr-sub" x={rtl ? x + COL_W - 16 : x + 16} y={y + 43} textAnchor="start" direction={rtl ? 'rtl' : 'ltr'}>
              {cut(sub, 38)}
            </text>
          </g>
        </g>
      );
    });
  }

  return (
    <svg className="dsr-diagram" viewBox={`0 0 ${String(W)} ${String(H)}`} role="img" aria-label={dossier.system.name}>
      <defs>
        {(['green', 'yellow', 'red'] as const).map((risk) => (
          <marker
            key={risk}
            id={`dsr-arrow-${risk}`}
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path className={`dsr-arrowhead risk-${risk}`} d="M0 0L10 5L0 10z" />
          </marker>
        ))}
      </defs>
      <text className="dsr-col-title" x={startX + COL_W / 2} y={22} textAnchor="middle">
        {labels.inbound}
      </text>
      <text className="dsr-col-title" x={endX + COL_W / 2} y={22} textAnchor="middle">
        {labels.outbound}
      </text>
      {column('inbound', inbound)}
      {column('outbound', outbound)}
      <g className={`dsr-center tier-${dossier.system.tier.toLowerCase()}`}>
        <rect x={centerX} y={centerY} width={CENTER_W} height={centerH} rx={12} />
        <text className="dsr-center-name" x={centerX + CENTER_W / 2} y={textY + 32} textAnchor="middle">
          {cut(dossier.system.name, 26)}
        </text>
        <text className="dsr-center-tier" x={centerX + CENTER_W / 2} y={textY + 54} textAnchor="middle">
          {dossier.system.tier}
        </text>
        {components.map((c, i) => (
          <text
            key={`${c.name}:${c.network}`}
            className="dsr-component"
            x={centerX + CENTER_W / 2}
            y={textY + 80 + i * LINE}
            textAnchor="middle"
            direction="ltr"
          >
            {cut(c.name === dossier.system.name ? c.network : `${c.name} · ${c.network}`, 40)}
          </text>
        ))}
        {extraComponents > 0 && (
          <text
            className="dsr-component"
            x={centerX + CENTER_W / 2}
            y={textY + 80 + components.length * LINE}
            textAnchor="middle"
            direction="ltr"
          >
            {labels.more(extraComponents)}
          </text>
        )}
      </g>
    </svg>
  );
}
