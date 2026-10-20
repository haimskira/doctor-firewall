/** Mirrors backend/app/api/schemas.py. */

export type Role = 'viewer' | 'optimizer' | 'approver' | 'admin';
export const ALL_ROLES: readonly Role[] = ['viewer', 'optimizer', 'approver', 'admin'];

export type Permission =
  | 'policy:read'
  | 'collect:run'
  | 'assets:write'
  | 'changeset:write'
  | 'deploy:approve'
  | 'audit:read'
  | 'users:manage'
  | 'fmc:manage'
  | 'conventions:manage';

export type Language = 'he' | 'en';

export interface Me {
  id: number;
  username: string;
  display_name: string;
  roles: Role[];
  permissions: Permission[];
  language: Language;
  must_change_password: boolean;
  csrf_token: string;
}

export interface User {
  id: number;
  username: string;
  display_name: string;
  roles: Role[];
  is_active: boolean;
  must_change_password: boolean;
  language: Language;
  created_at: string;
  last_login_at: string | null;
}

export interface FmcConnection {
  id: number;
  name: string;
  host: string;
  port: number;
  username: string;
  domain_uuid: string | null;
  server_version: string | null;
  last_test_at: string | null;
  last_test_ok: boolean | null;
  sync_interval_minutes: number | null;
}

export interface FmcTestResult {
  ok: boolean;
  server_version: string | null;
  domain_uuid: string | null;
  error: string | null;
}

export interface AuditRecord {
  id: number;
  ts: string;
  actor: string;
  action: string;
  outcome: 'success' | 'failure' | 'denied';
  cluster: string | null;
  target: string | null;
  source_ip: string | null;
  details: Record<string, unknown>;
}

export interface AuditVerify {
  ok: boolean;
  checked: number;
  head_id: number | null;
  head_hash: string | null;
  broken_at_id: number | null;
  reason: string | null;
}

// ---- phase 1: snapshots & inventory (mirrors backend/app/api/inventory.py) ----

export type SnapshotStatus = 'pending' | 'running' | 'complete' | 'failed';

export interface Snapshot {
  id: number;
  connection_id: number | null;
  connection_name: string;
  status: SnapshotStatus;
  requested_by: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  analyzed_at: string | null;
  fmc_version: string | null;
  error: string | null;
  error_detail: string | null;
  stats: Partial<Record<'objects' | 'rules' | 'policies' | 'clusters' | 'interfaces' | 'routes' | 'stub_objects', number>> & {
    naming?: Partial<Record<string, NamingStats>>;
  };
}

export interface NamingStats {
  compliant: number;
  noncompliant: number;
  proposed: number;
}

export interface ClusterMember {
  id: string;
  name: string;
  role: string;
}

export type PolicyKind = 'access' | 'prefilter' | 'decryption' | 'identity' | 'nat' | 'intrusion' | 'file' | 'dns';
export const RULE_POLICY_KINDS: readonly PolicyKind[] = ['access', 'prefilter', 'decryption', 'identity', 'nat'];

export interface GoverningPolicy {
  id: string;
  name: string;
  kind: PolicyKind;
  via: string;
  rule_count: number;
}

export interface PolicyInfo {
  id: string;
  kind: PolicyKind;
  name: string;
  default_action: string;
  rule_count: number;
  links: { relation: string; id: string; name: string; type: string }[];
  attrs: Record<string, unknown>;
  clusters: string[];
}

export interface Cluster {
  fmc_id: string;
  name: string;
  kind: string;
  sw_version: string;
  model: string;
  members: ClusterMember[];
  policy_fmc_id: string | null;
  policy_name: string | null;
  rule_count: number;
  policies: GoverningPolicy[];
  ace_total: number | null;
  ace_limit: number;
  ace_limit_verified: boolean;
}

export interface RefItem {
  id: string | null;
  name: string;
  kind: string | null;
  literal: string | null;
}

export type RuleFieldName =
  | 'src_zone'
  | 'dst_zone'
  | 'src_net'
  | 'dst_net'
  | 'src_port'
  | 'dst_port'
  | 'app'
  | 'url'
  | 'src_sgt'
  | 'dst_sgt'
  | 'src_dyn'
  | 'dst_dyn'
  | 'user'
  | 'vlan'
  | 'nat_orig_src'
  | 'nat_trans_src'
  | 'nat_orig_dst'
  | 'nat_trans_dst'
  | 'nat_orig_sport'
  | 'nat_trans_sport'
  | 'nat_orig_dport'
  | 'nat_trans_dport';

export interface RuleRow {
  id: string;
  rule_type: string | null;
  index: number;
  section: string;
  category: string;
  name: string;
  enabled: boolean;
  action: string;
  hit_count: number | null;
  last_hit: string | null;
  ips_policy: string | null;
  file_policy: string | null;
  log_begin: boolean;
  log_end: boolean;
  refs: Partial<Record<RuleFieldName, RefItem[]>>;
  score?: number | null;
  ace_count?: number | null;
  reasons?: ScoreReason[];
  src_tiers?: string[];
  dst_tiers?: string[];
  shadowed_by?: string | null;
  dead?: boolean;
  recommendations?: RuleRecTag[];
}

export interface RuleRecTag {
  id: number;
  kind: RecommendationKind;
  deploy_cost: number;
  status: 'open' | 'accepted';
}

export interface ScoreReason {
  code: string;
  points: number;
  [detail: string]: unknown;
}

export interface ScoredRule {
  policy_fmc_id: string;
  policy_name: string;
  rule_id: string;
  rule_index: number;
  rule_name: string;
  action: string;
  score: number;
  ace_count: number;
  reasons: ScoreReason[];
  dst_tiers: string[];
}

export type Tier = 'CORE' | 'GOLD' | 'SILVER' | 'BRONZE' | 'USERS';
export const TIERS: readonly Tier[] = ['CORE', 'GOLD', 'SILVER', 'BRONZE', 'USERS'];

export interface Asset {
  id: number;
  network: string;
  system: string;
  tier: Tier;
  system_type: string;
  user_type: string | null;
  ports: string;
  notes: string;
  source: 'manual' | 'csv' | 'bootstrap';
  confirmed: boolean;
  updated_by: string;
}

export interface ClusterLimits {
  cluster_fmc_id: string;
  ace_limit: number;
  ace_limit_verified: boolean;
  deploy_change_limit: number;
  deploy_limit_verified: boolean;
  is_default: boolean;
}

/** A contiguous run of rules with the same section and category (an FMC section band). */
export interface RuleGroup {
  section: string;
  category: string;
  /** 0-based position of the first rule in the (filtered) ordered list. */
  start: number;
  count: number;
  first_index: number;
  last_index: number;
}

export interface RulesPage {
  policy_fmc_id: string;
  policy_kind: PolicyKind;
  policy_name: string;
  default_action: string;
  /** Present on the first page (offset 0) only. */
  groups: RuleGroup[];
  categories: string[];
  total: number;
  offset: number;
  rows: RuleRow[];
}

export interface FwObject {
  id: string;
  name: string;
  kind: string;
  fmc_type: string;
  value: string | null;
  stub: boolean;
  rule_refs: number;
  member_of: number;
}

export interface ObjectsPage {
  total: number;
  offset: number;
  rows: FwObject[];
}

export interface MembershipEdge {
  group_id: string;
  group_name: string;
  child_id: string;
  depth: number;
}

export interface Usage {
  policy_fmc_id: string;
  policy_kind: PolicyKind;
  policy_name: string;
  rule_id: string;
  rule_index: number;
  rule_name: string;
  field: RuleFieldName;
  via_id: string;
  via_name: string;
}

export interface ObjectDetail {
  object: FwObject;
  attrs: Record<string, unknown>;
  members: RefItem[];
  member_of: MembershipEdge[];
  used_by: Usage[];
  used_by_total: number;
}

export type Severity = 'info' | 'low' | 'medium' | 'high';

export interface FindingRow {
  id: number;
  kind: string;
  severity: Severity;
  policy_fmc_id: string | null;
  title: string;
  details: Record<string, unknown>;
}

export interface FindingsPage {
  total: number;
  offset: number;
  summary: Record<string, Partial<Record<Severity, number>>>;
  rows: FindingRow[];
}

export interface ClusterNetwork {
  interfaces: {
    name: string;
    ifname: string;
    kind: string;
    enabled: boolean;
    ipv4: string | null;
    vlan: number | null;
    zone: string | null;
  }[];
  routes: {
    kind: 'static' | 'connected';
    network: string | null;
    network_name: string;
    interface: string;
    gateway: string | null;
    gateway_is_literal: boolean;
    metric: number;
  }[];
  bgp: { as_number: string | null; router_id: string | null; neighbors: { address: string; remote_as: string }[] }[];
}

// ---- phase 3: recommendations and naming convention (mirrors app/api/recommendations.py) ----

export type RecommendationKind =
  | 'remove_shadowed_rule'
  | 'remove_dead_rule'
  | 'remove_unused_object'
  | 'merge_duplicate_objects'
  | 'merge_groups'
  | 'split_group'
  | 'split_rule'
  | 'merge_rules'
  | 'tighten_source'
  | 'tighten_ports'
  | 'rename_role'
  | 'rename_convention'
  | 'literal_to_object';

export const RECOMMENDATION_KINDS: readonly RecommendationKind[] = [
  'remove_shadowed_rule',
  'remove_dead_rule',
  'split_rule',
  'merge_rules',
  'tighten_source',
  'tighten_ports',
  'split_group',
  'merge_groups',
  'merge_duplicate_objects',
  'literal_to_object',
  'rename_role',
  'rename_convention',
  'remove_unused_object',
];

export type DecisionStatus = 'accepted' | 'dismissed';

export interface RecommendationDecision {
  status: DecisionStatus;
  note: string;
  decided_by: string;
  decided_at: string;
}

export interface RecTarget {
  type: 'rule' | 'object' | 'literal';
  id: string;
  name: string;
  index?: number;
  kind?: string;
}

export interface Recommendation {
  id: number;
  kind: RecommendationKind;
  policy_fmc_id: string | null;
  title: string;
  principle: string;
  priority: number;
  targets: RecTarget[];
  display: 'inline' | 'split';
  deploy_cost: number;
  ace_delta: number;
  score_delta: number | null;
  warnings: string[];
  fingerprint: string;
  decision: RecommendationDecision | null;
}

export type RowStatus = 'unchanged' | 'modified' | 'new' | 'removed';

export interface PreviewRule {
  id: string | null;
  index: number | null;
  name: string;
  action: string;
  enabled: boolean;
  section: string;
  category: string;
  fields: Partial<Record<RuleFieldName, string[]>>;
  status?: RowStatus;
  changes?: Partial<Record<RuleFieldName | 'name', { added: string[]; removed: string[] }>>;
}

export interface PreviewObject {
  id: string | null;
  name: string;
  kind: string;
  value?: string | null;
  tier?: string;
  members?: string[];
  references?: number;
  status: 'unchanged' | 'kept' | 'removed' | 'new';
}

export interface AffectedRule {
  id: string;
  index: number;
  name: string;
  policy_id: string;
  policy_name: string;
}

export interface RecommendationPreview {
  policy?: { id: string; name: string; kind: PolicyKind };
  before?: PreviewRule[];
  after?: PreviewRule[];
  objects?: { before: PreviewObject[]; after: PreviewObject[] };
  rename?: { from: string; to: string; kind: string };
  literal?: { value: string; kind: string; object: string; object_id: string | null; create: boolean };
  affected_rules?: { total: number; sample: AffectedRule[] };
  affected_groups?: string[];
  routes?: number;
  hits?: { hit_count: number | null; last_hit: string | null };
}

export interface RecommendationDetail extends Recommendation {
  preview: RecommendationPreview;
}

export interface KindSummary {
  count: number;
  deploy_cost: number;
  ace_delta: number;
}

export interface RecommendationsPage {
  total: number;
  offset: number;
  summary: Partial<Record<RecommendationKind, KindSummary>>;
  accepted: KindSummary;
  rows: Recommendation[];
}

export type ConventionKind = 'host' | 'network' | 'range' | 'fqdn' | 'network_group' | 'port' | 'port_group' | 'rule';
export const CONVENTION_KINDS: readonly ConventionKind[] = [
  'host',
  'network',
  'range',
  'fqdn',
  'network_group',
  'port',
  'port_group',
  'rule',
];

export interface NamingConvention {
  kind: ConventionKind;
  template: string;
  letter_case: 'upper' | 'lower' | 'keep';
  enabled: boolean;
  updated_by: string;
  updated_at: string;
}

export interface ConventionCatalog {
  kinds: Record<ConventionKind, string[]>;
  conventions: NamingConvention[];
}
