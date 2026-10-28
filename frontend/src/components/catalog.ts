import type { RecommendationKind } from '../api/types';

/** Every finding kind the analysis produces (mirrors app/analysis). */
export const FINDING_KINDS = [
  'ace_cluster_limit',
  'shadowed_rule',
  'group_cycle',
  'identical_rules',
  'dead_rule',
  'overlap_conflict',
  'deep_nesting',
  'ace_heavy_rule',
  'duplicate_object',
  'duplicate_membership',
  'inline_literal',
  'unused_object',
  'disabled_rule',
] as const;

/** Recommendation kinds that change what is allowed by design (app.models.recommendations). */
export const CHANGING_KINDS: ReadonlySet<RecommendationKind> = new Set<RecommendationKind>([
  'remove_dead_rule',
  'tighten_source',
  'tighten_ports',
  'add_inspection',
  'ssl_decrypt_inbound',
]);
