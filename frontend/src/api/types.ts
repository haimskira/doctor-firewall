/** Mirrors backend/app/api/schemas.py. */

export type Role = 'viewer' | 'optimizer' | 'approver' | 'admin';
export const ALL_ROLES: readonly Role[] = ['viewer', 'optimizer', 'approver', 'admin'];

export type Permission =
  | 'policy:read'
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
