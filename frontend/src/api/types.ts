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

export type AuthProviderName = 'local' | 'ldap' | 'tacacs';

/** Everything tying one object into the rulebase (GET .../objects/{id}/relations). */
export interface ObjectRelations {
  object: { id: string; name: string; kind: string; value: string | null };
  nodes: {
    id: string;
    kind: string;
    label: string;
    role: 'self' | 'ancestor' | 'descendant' | 'rule' | 'overlap';
    depth: number;
    detail: string;
  }[];
  edges: { source: string; target: string; kind: 'member' | 'uses' | 'overlap'; label: string }[];
  issues: {
    kind: 'redundant_reference' | 'redundant_member';
    where_id: string;
    where_name: string;
    removed: string;
    kept: string;
    recommendation_id: number | null;
  }[];
  truncated: boolean;
}
export type Theme = 'system' | 'light' | 'dark';
export const AUTH_PROVIDERS: readonly AuthProviderName[] = ['local', 'ldap', 'tacacs'];

export interface Me {
  id: number;
  username: string;
  display_name: string;
  auth_provider: AuthProviderName;
  roles: Role[];
  permissions: Permission[];
  language: Language;
  theme: Theme;
  must_change_password: boolean;
  csrf_token: string;
}

export interface User {
  id: number;
  username: string;
  display_name: string;
  auth_provider: AuthProviderName;
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

export type PolicyKind = 'access' | 'prefilter' | 'decryption' | 'identity' | 'nat' | 'intrusion' | 'file' | 'dns' | 'unknown';
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
  group_id: number | null;
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

export type AssetKind = 'system' | 'server' | 'user' | 'user_segment';
export const ASSET_KINDS: readonly AssetKind[] = ['system', 'server', 'user', 'user_segment'];

/** An asset (system, server, user or user segment) with its components. */
export interface AssetGroup {
  id: number;
  name: string;
  kind: AssetKind;
  tier: Tier;
  user_type: string | null;
  owner: string;
  description: string;
  updated_by: string;
  components: Asset[];
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
    kind: 'static' | 'connected' | 'dynamic';
    network: string | null;
    network_name: string;
    interface: string;
    gateway: string | null;
    gateway_is_literal: boolean;
    metric: number;
    protocol: string;
    distance: number | null;
  }[];
  bgp: { as_number: string | null; router_id: string | null; neighbors: { address: string; remote_as: string }[] }[];
  runtime: RuntimeRoutesStatus | null;
}

/** The live routing table of a cluster ("show route" through the FMC). */
export interface RuntimeRoutesStatus {
  status: 'ok' | 'unsupported' | 'unavailable' | 'mismatch' | 'disabled';
  routes: number;
  device?: string;
  skipped_lines?: number;
}

export interface RouteMatch {
  kind: 'static' | 'connected' | 'dynamic';
  protocol: string;
  network: string;
  interface: string;
  zone: string | null;
  gateway: string | null;
  distance: number;
}

export interface RouteLookup {
  ip: string;
  best: RouteMatch | null;
  matches: RouteMatch[];
  runtime_status: RuntimeRoutesStatus['status'] | null;
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
  | 'literal_to_object'
  | 'add_inspection'
  | 'ssl_exempt_core'
  | 'ssl_decrypt_inbound'
  | 'remove_redundant_reference'
  | 'remove_redundant_member';

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
  'add_inspection',
  'ssl_exempt_core',
  'ssl_decrypt_inbound',
  'remove_redundant_reference',
  'remove_redundant_member',
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
  executable: boolean;
  blocked: string[];
  /** A batch deployed after this snapshot already carried it out. */
  applied?: boolean;
  /** 'preserves': no flow's verdict changes; 'changes': by design (less access, more inspection). */
  behavior?: 'preserves' | 'changes';
  staged_in?: number | null;
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
  fields: Partial<Record<PreviewFieldName, string[]>>;
  status?: RowStatus;
  changes?: Partial<Record<PreviewFieldName | 'name' | 'action', { added: string[]; removed: string[] }>>;
}

/** Rule fields in a preview: the match fields plus the attached inspection policies. */
export type PreviewFieldName = RuleFieldName | 'ips_policy' | 'file_policy';

// ---- phase 6: tier -> inspection profile (mirrors app/api/recommendations.py) ----

export type InspectionTier = 'GOLD' | 'SILVER' | 'BRONZE';

export interface InspectionProfile {
  tier: InspectionTier;
  ips_policy: string | null;
  file_policy: string | null;
  configured: boolean;
  min_level: number;
  file_required: boolean;
}

export interface InspectionPolicyChoice {
  name: string;
  level: number | null;
}

export interface InspectionCatalog {
  profiles: InspectionProfile[];
  intrusion_policies: InspectionPolicyChoice[];
  file_policies: InspectionPolicyChoice[];
  snapshot_id: number | null;
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
  map?: { before: MapChangeEdge[]; after: MapChangeEdge[] };
  // phase 6: destination tier, systems concerned, rules that reach them over TLS
  tier?: string;
  systems?: string[];
  rules?: { policy: string; index: number; name: string; id: string }[];
}

export interface PlanOp {
  op: 'create_object' | 'update_group' | 'rename_object' | 'delete_object' | 'create_rule' | 'update_rule' | 'delete_rule';
  name?: string;
  rule_name?: string;
  object_name?: string;
  type?: string;
  kind?: string;
  set?: Partial<Record<RuleFieldName, { id?: string; temp?: string; name?: string; literal?: string }[]>>;
}

export interface Plan {
  version?: number;
  ops?: PlanOp[];
  executable?: boolean;
  blocked?: string[];
}

export interface RecommendationDetail extends Recommendation {
  preview: RecommendationPreview;
  plan: Plan;
}

export interface KindSummary {
  count: number;
  deploy_cost: number;
  ace_delta: number;
}

export interface StaleSnapshot {
  changeset_id: number;
  title: string;
  batch: number;
  at: string;
}

export interface RecommendationsPage {
  total: number;
  offset: number;
  /** This system changed the FMC after the snapshot was taken. */
  stale?: StaleSnapshot | null;
  summary: Partial<Record<RecommendationKind, KindSummary>>;
  accepted: KindSummary;
  /** Accepted recommendations already in an open changeset. */
  accepted_staged: number;
  staged_changesets: { id: number; title: string }[];
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

// ---- phase 4: connectivity map (mirrors app/api/connectivity.py) ----

export type MapView = 'assets' | 'system' | 'users';
export type MapRisk = 'green' | 'yellow' | 'red';

export interface MapNode {
  id: string;
  label: string;
  tier: string | null;
  user_type: string | null;
  networks: string[];
}

export interface MapEdgeRule {
  id: string;
  name: string;
  index: number;
  risk: MapRisk;
  score: number | null;
  policy_id: string;
}

export interface MapEdge {
  id: string;
  src: string;
  dst: string;
  risk: MapRisk;
  rule_count: number;
  hits: number;
  min_score: number | null;
  reasons: string[];
  services: string[];
  rules: MapEdgeRule[];
  risk_rules: Partial<Record<MapRisk, number>>;
  risk_hits: Partial<Record<MapRisk, number>>;
}

export interface ConnectivityMap {
  view: MapView;
  nodes: MapNode[];
  edges: MapEdge[];
  total_edges: number;
  truncated: boolean;
  risk_counts: Record<MapRisk, number>;
}

export interface MapChangeEdge {
  src: string;
  dst: string;
  risk: MapRisk;
}

// ---- summary dashboard (mirrors app/api/dashboard.py) ----

export interface Counted {
  key: string;
  count: number;
  extra: Record<string, number>;
}

export interface DashboardData {
  snapshot: {
    id: number;
    connection_name: string;
    fmc_version: string | null;
    created_at: string;
    finished_at: string | null;
    analyzed_at: string | null;
  };
  totals: Record<'rules' | 'policies' | 'objects' | 'clusters' | 'findings' | 'recommendations' | 'dead_rules' | 'shadowed_rules', number>;
  findings_by_severity: Record<Severity, number>;
  findings_by_kind: Counted[];
  recommendations_by_kind: Counted[];
  score_buckets: Counted[];
  rules_by_action: Counted[];
  clusters: { id: string; name: string; rule_count: number; ace_total: number | null; ace_limit: number; ace_limit_verified: boolean }[];
  map_risk: Record<MapRisk, number>;
  riskiest_connections: { src: string; dst: string; risk: MapRisk; rule_count: number; hits: number }[];
  worst_rules: { id: string; name: string; index: number; policy_id: string; policy_name: string; score: number }[];
}

// ---- phase 5: changesets and batches (mirrors app/api/changesets.py) ----

export type ChangesetStatus = 'open' | 'in_progress' | 'completed' | 'failed' | 'cancelled';
export type BatchStatus = 'pending' | 'approved' | 'running' | 'deployed' | 'failed' | 'rolled_back' | 'cancelled' | 'reverted';

export interface BatchResult {
  op: string;
  name?: string;
  id?: string;
  detail?: string;
}

export interface ProofDifference {
  flow: Record<string, string | number>;
  before: { verdict: (string | null)[]; rule: string | null };
  after: { verdict: (string | null)[]; rule: string | null };
}

export interface TrafficProof {
  ok: boolean;
  exhaustive: boolean;
  flows: number;
  differences: number;
  behavior: 'preserves' | 'changes';
  matches_plan?: boolean;
  seconds: number;
  computed_at: string;
  policies: { id: string; name: string; touched: number; flows: number; exhaustive: boolean; differences: ProofDifference[]; difference_count?: number }[];
}

export interface ChangesetBatch {
  seq: number;
  status: BatchStatus;
  op_count: number;
  deploy_limit: number;
  clusters: string[];
  approved_by: string | null;
  approved_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  results: BatchResult[];
  /** Saved undo steps not yet undone. */
  undo_pending: number;
  /** The rollback was interrupted (FMC unreachable) and can be finished. */
  rollback_resumable: boolean;
  /** Traffic proof of the plan (null while computing) and of what the FMC held before deploying. */
  proof?: TrafficProof | null;
  proof_after?: TrafficProof | null;
  changes_acknowledged_by?: string | null;
}

export interface ChangesetItem {
  fingerprint: string;
  kind: RecommendationKind;
  title: string;
  policy_fmc_id: string | null;
  batch_seq: number;
  op_count: number;
  plan: Plan;
}

export interface Changeset {
  id: number;
  snapshot_id: number | null;
  connection_id: number | null;
  title: string;
  ticket_id: string;
  status: ChangesetStatus;
  deploy_limit: number;
  deploy_limit_verified: boolean;
  created_by: string;
  created_at: string;
  op_count: number;
  item_count: number;
  batches: ChangesetBatch[];
}

export interface ChangesetDetail extends Changeset {
  items: ChangesetItem[];
}

/* ---- attack surface / blast radius ---- */

export type AttackMode = 'to' | 'from';

export interface AttackTarget {
  id: string;
  label: string;
  tier: string;
  networks: string[];
}

export interface AttackRule {
  policy_id: string;
  policy: string;
  id: string;
  name: string;
  index: number;
  action: string;
  inspected: boolean;
  partial: boolean;
  default: boolean;
  hits: number | null;
}

export interface AttackNode {
  id: string;
  label: string;
  tier: string | null;
  kind: 'origin' | 'anywhere' | 'unclassified' | 'system';
  depth: number;
  networks: string[];
}

export interface AttackEdge {
  id: string;
  src: string;
  dst: string;
  depth: number;
  services: string[];
  apps: string[];
  rules: AttackRule[];
  rule_count: number;
  risk: 'green' | 'yellow' | 'red';
}

export interface AttackHop {
  services: string[];
  apps: string[];
  rules: AttackRule[];
  rule_count: number;
}

export interface AttackPath {
  score: number;
  reasons: string[];
  steps: { nodes: string[]; networks: string[] }[];
  hops: AttackHop[];
}

export interface AttackSurface {
  mode: AttackMode;
  origin: { nodes: string[]; networks: string[] };
  nodes: AttackNode[];
  edges: AttackEdge[];
  paths: AttackPath[];
  summary: {
    paths: number;
    entry_points: number;
    anywhere: boolean;
    shortest: number | null;
    services: string[];
    reached: number;
    truncated: boolean;
  };
}

/* ---- background jobs ---- */

export type JobKind = 'collect' | 'analyze' | 'batch' | 'rollback' | 'audit_verify' | 'proof' | 'revert';
export type JobStatus = 'queued' | 'running' | 'done' | 'failed';

export interface JobRun {
  id: number;
  kind: JobKind;
  title: string;
  requested_by: string;
  status: JobStatus;
  progress: number;
  step: string;
  step_args: Record<string, string | number>;
  error: string | null;
  snapshot_id: number | null;
  batch_id: number | null;
  changeset_id: number | null;
  created_at: string;
  started_at: string | null;
  updated_at: string | null;
  finished_at: string | null;
}

export interface JobsList {
  active: number;
  rows: JobRun[];
}
