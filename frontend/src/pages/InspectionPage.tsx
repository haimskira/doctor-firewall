import { useState } from 'react';
import type { SyntheticEvent } from 'react';
import { SortedTable } from '../components/sort';

import { api, errorCode } from '../api/client';
import type { InspectionCatalog, InspectionPolicyChoice, InspectionProfile } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { Alert } from '../components/common';
import { useApi } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';

/**
 * Tier -> intrusion / file policy: which FMC policies implement the doctrine's inspection
 * for each destination tier (the input of the "add inspection" recommendations).
 */
export function InspectionPage() {
  const { t, tError } = useI18n();
  const { can } = useAuth();
  const catalog = useApi<InspectionCatalog>('/api/inspection-profiles');
  const [notice, setNotice] = useState<string | null>(null);
  const editable = can('conventions:manage');

  return (
    <div className="stack">
      <div>
        <h1>{t('inspection.title')}</h1>
        <p className="muted small">{t('inspection.help')}</p>
      </div>
      {catalog.error !== null && <Alert kind="error">{tError(catalog.error)}</Alert>}
      {notice !== null && <Alert kind="success">{notice}</Alert>}
      {catalog.data !== null && catalog.data.snapshot_id === null && <Alert kind="info">{t('inspection.noSnapshot')}</Alert>}
      {catalog.data !== null && (
        <section className="card">
          <table>
            <SortedTable
              rows={catalog.data.profiles}
              columns={{ tier: (profile) => profile.tier, ips: (profile) => profile.ips_policy, file: (profile) => profile.file_policy }}
              head={(th) => (
                <tr>
                  {th('tier', t('inspection.tier'))}
                  <th>{t('inspection.doctrine')}</th>
                  {th('ips', t('inspection.ips'))}
                  {th('file', t('inspection.file'))}
                  <th>{t('common.actions')}</th>
                </tr>
              )}
            >
              {(profile) => (
                <ProfileRow
                  key={`${profile.tier}-${profile.ips_policy ?? ''}-${profile.file_policy ?? ''}-${String(profile.configured)}`}
                  profile={profile}
                  intrusion={catalog.data?.intrusion_policies ?? []}
                  files={catalog.data?.file_policies ?? []}
                  editable={editable}
                  onSaved={() => {
                    setNotice(t('inspection.saved'));
                    catalog.reload();
                  }}
                />
              )}
            </SortedTable>
          </table>
        </section>
      )}
    </div>
  );
}

function PolicySelect({
  label,
  value,
  choices,
  withLevel,
  formId,
  onChange,
}: {
  label: string;
  value: string;
  choices: InspectionPolicyChoice[];
  withLevel: boolean;
  formId: string;
  onChange: (value: string) => void;
}) {
  const { t } = useI18n();
  const known = choices.some((c) => c.name === value);
  return (
    <select
      form={formId}
      aria-label={label}
      value={value}
      onChange={(e) => {
        onChange(e.target.value);
      }}
    >
      <option value="">{t('inspection.none')}</option>
      {!known && value !== '' && (
        <option value={value}>
          {value} ({t('inspection.missing')})
        </option>
      )}
      {choices.map((c) => (
        <option key={c.name} value={c.name}>
          {withLevel && c.level !== null ? `${c.name} · ${t('inspection.level', { level: c.level })}` : c.name}
        </option>
      ))}
    </select>
  );
}

function ProfileRow({
  profile,
  intrusion,
  files,
  editable,
  onSaved,
}: {
  profile: InspectionProfile;
  intrusion: InspectionPolicyChoice[];
  files: InspectionPolicyChoice[];
  editable: boolean;
  onSaved: () => void;
}) {
  const { t, tError } = useI18n();
  const [ips, setIps] = useState(profile.ips_policy ?? '');
  const [file, setFile] = useState(profile.file_policy ?? '');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const formId = `inspection-${profile.tier}`;

  async function call(action: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      onSaved();
    } catch (err) {
      setError(errorCode(err));
    } finally {
      setBusy(false);
    }
  }

  function save(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    void call(() =>
      api(`/api/inspection-profiles/${profile.tier}`, 'PUT', {
        ips_policy: ips === '' ? null : ips,
        file_policy: file === '' ? null : file,
      }),
    );
  }

  return (
    <tr>
      <td>
        <span className={`tier tier-${profile.tier.toLowerCase()}`}>{profile.tier}</span>
        {!profile.configured && <div className="muted small">{t('inspection.default')}</div>}
        {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      </td>
      <td className="small">{t(`inspection.doctrine.${profile.tier}`)}</td>
      <td>
        {editable ? (
          <form id={formId} onSubmit={save}>
            <PolicySelect
              label={`${t('inspection.ips')} — ${profile.tier}`}
              value={ips}
              choices={intrusion}
              withLevel
              formId={formId}
              onChange={setIps}
            />
          </form>
        ) : (
          (profile.ips_policy ?? t('inspection.none'))
        )}
      </td>
      <td>
        {editable ? (
          <PolicySelect
            label={`${t('inspection.file')} — ${profile.tier}`}
            value={file}
            choices={files}
            withLevel={false}
            formId={formId}
            onChange={setFile}
          />
        ) : (
          (profile.file_policy ?? t('inspection.none'))
        )}
      </td>
      <td className="actions">
        {editable && (
          <>
            <button type="submit" form={formId} disabled={busy}>
              {t('common.save')}
            </button>
            {profile.configured && (
              <button
                type="button"
                className="secondary"
                disabled={busy}
                onClick={() => void call(() => api(`/api/inspection-profiles/${profile.tier}`, 'DELETE'))}
              >
                {t('inspection.reset')}
              </button>
            )}
          </>
        )}
      </td>
    </tr>
  );
}
