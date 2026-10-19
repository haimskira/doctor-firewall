/** Mirrors backend/app/api/schemas.py. */

export type Role = 'viewer' | 'optimizer' | 'approver' | 'admin';
export const ALL_ROLES: readonly Role[] = ['viewer', 'optimizer', 'approver', 'admin'];

export type Permission =
  | 'policy:read'
  | 'collect:run'
  | 'changeset:write'
  | 'deploy:approve'
  | 'audit:read'
  | 'users:manage'
  | 'fmc:manage';

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
  stats: Partial<Record<'objects' | 'rules' | 'policies' | 'clusters' | 'interfaces' | 'routes' | 'stub_objects', number>>;
}

export interface ClusterMember {
  id: string;
  name: string;
  role: string;
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
  | 'vlan';

export interface RuleRow {
  id: string;
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
}

export interface RulesPage {
  policy_fmc_id: string;
  policy_name: string;
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
