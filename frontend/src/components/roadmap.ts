import type { RecommendationKind } from '../api/types';

/** The clean-up phases in order (mirrors app/analysis/roadmap.py). */
export const PHASES = ['never_match', 'objects', 'structure', 'access', 'closing'] as const;
export type Phase = (typeof PHASES)[number];

export const PHASE_OF: Record<RecommendationKind, Phase> = {
  remove_disabled_rule: 'never_match',
  remove_shadowed_rule: 'never_match',
  merge_duplicate_objects: 'objects',
  merge_groups: 'objects',
  remove_redundant_reference: 'objects',
  remove_redundant_member: 'objects',
  compact_group: 'objects',
  literal_to_object: 'objects',
  rename_role: 'objects',
  rename_convention: 'objects',
  split_group: 'structure',
  split_rule: 'structure',
  merge_rules: 'structure',
  remove_dead_rule: 'access',
  tighten_source: 'access',
  tighten_ports: 'access',
  add_inspection: 'access',
  ssl_exempt_core: 'access',
  ssl_decrypt_inbound: 'access',
  remove_unused_object: 'closing',
};

const PHASE_BY_KIND = new Map<string, Phase>(Object.entries(PHASE_OF));

/** The roadmap phase of a recommendation kind. */
export function phaseOf(kind: RecommendationKind): Phase {
  return PHASE_BY_KIND.get(kind) ?? 'closing';
}

export function isPhase(value: string | null): value is Phase {
  return value !== null && (PHASES as readonly string[]).includes(value);
}

/** True when ``kind`` belongs to a phase after ``current`` (its turn has not come yet). */
export function isAhead(kind: RecommendationKind, current: string | null): boolean {
  if (!isPhase(current)) return false;
  return PHASES.indexOf(phaseOf(kind)) > PHASES.indexOf(current);
}

export interface RoadmapCounts {
  total: number;
  open: number;
  accepted: number;
  staged: number;
  dismissed: number;
  ace_delta: number;
}

export interface Roadmap {
  snapshot_id: number;
  prepare: { code: 'assets' | 'limits' | 'hits' | 'fresh'; ok: boolean; args: Record<string, number> }[];
  phases: (RoadmapCounts & {
    name: Phase;
    status: 'done' | 'current' | 'next';
    behavior: 'preserves' | 'changes';
    kinds: (RoadmapCounts & { kind: RecommendationKind })[];
  })[];
  current: Phase | null;
}
