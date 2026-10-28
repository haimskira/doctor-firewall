import type { PolicyInfo } from '../api/types';
import { useApi, useQueryParam } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';

export interface PolicyScope {
  /** The chosen access policy, or null for "all" (what the devices enforce). */
  policy: string | null;
  setPolicy: (id: string | null) => void;
  policies: PolicyInfo[];
  selected: PolicyInfo | null;
}

/** ``?policy=`` — the access policy a view is narrowed to (shared by every insight page). */
export function usePolicyScope(snapshotId: number | null): PolicyScope {
  const [param, setParam] = useQueryParam('policy');
  const list = useApi<PolicyInfo[]>(snapshotId === null ? null : `/api/snapshots/${String(snapshotId)}/policies`);
  const policies = (list.data ?? []).filter((p) => p.kind === 'access');
  const selected = policies.find((p) => p.id === param) ?? null;
  return { policy: selected?.id ?? null, setPolicy: setParam, policies, selected };
}

export function PolicyPicker({ scope }: { scope: PolicyScope }) {
  const { t } = useI18n();
  if (scope.policies.length === 0) return null;
  return (
    <label className="inline-field policy-picker">
      {t('scope.policy')}
      <select
        value={scope.policy ?? ''}
        onChange={(e) => {
          scope.setPolicy(e.target.value === '' ? null : e.target.value);
        }}
      >
        <option value="">{t('scope.all')}</option>
        {scope.policies.map((p) => (
          <option key={p.id} value={p.id}>
            {p.name} ({p.rule_count}){p.clusters.length === 0 ? ` · ${t('pe.unassigned')}` : ''}
          </option>
        ))}
      </select>
    </label>
  );
}

/** Under a picker: what the chosen scope means (shared items, or a policy no device enforces). */
export function ScopeNote({ scope, traffic = false }: { scope: PolicyScope; traffic?: boolean }) {
  const { t } = useI18n();
  if (scope.selected === null) return traffic ? <p className="muted small">{t('scope.allTraffic')}</p> : null;
  if (scope.selected.clusters.length === 0) {
    return <p className="scope-note warn small">{t(traffic ? 'scope.unassignedTraffic' : 'scope.unassigned', { name: scope.selected.name })}</p>;
  }
  return traffic ? null : <p className="muted small">{t('scope.shared')}</p>;
}
