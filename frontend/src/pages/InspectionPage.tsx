import { useState } from 'react';
import type { SyntheticEvent } from 'react';

import { api, errorCode } from '../api/client';
import type { InspectionCatalog, InspectionPolicyChoice, InspectionProfile } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { Alert } from '../components/common';
import { useApi } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';

/**
 * The organisation's one intrusion policy and one file policy: the input of the "add intrusion
 * policy" and "add file policy" recommendations. Left empty, each is the policy most allow rules
 * already carry.
 */
export function InspectionPage() {
  const { t, tError } = useI18n();
  const { can } = useAuth();
  const catalog = useApi<InspectionCatalog>('/api/inspection-profile');
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
          <ProfileForm
            key={`${catalog.data.profile.ips_policy ?? ''}-${catalog.data.profile.file_policy ?? ''}-${String(catalog.data.profile.configured)}`}
            profile={catalog.data.profile}
            intrusion={catalog.data.intrusion_policies}
            files={catalog.data.file_policies}
            editable={editable}
            onSaved={() => {
              setNotice(t('inspection.saved'));
              catalog.reload();
            }}
          />
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
  onChange,
}: {
  label: string;
  value: string;
  choices: InspectionPolicyChoice[];
  withLevel: boolean;
  onChange: (value: string) => void;
}) {
  const { t } = useI18n();
  const known = choices.some((c) => c.name === value);
  return (
    <select
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

function ProfileForm({
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
      api('/api/inspection-profile', 'PUT', {
        ips_policy: ips === '' ? null : ips,
        file_policy: file === '' ? null : file,
      }),
    );
  }

  return (
    <form onSubmit={save} className="stack">
      {error !== null && <Alert kind="error">{tError(error)}</Alert>}
      <label>
        <span>{t('inspection.ips')}</span>
        {editable ? (
          <PolicySelect label={t('inspection.ips')} value={ips} choices={intrusion} withLevel onChange={setIps} />
        ) : (
          <div>{profile.ips_policy ?? t('inspection.none')}</div>
        )}
        {profile.ips_default && <div className="muted small">{t('inspection.default')}</div>}
        <div className="muted small">{t('inspection.ipsHelp')}</div>
      </label>
      <label>
        <span>{t('inspection.file')}</span>
        {editable ? (
          <PolicySelect label={t('inspection.file')} value={file} choices={files} withLevel={false} onChange={setFile} />
        ) : (
          <div>{profile.file_policy ?? t('inspection.none')}</div>
        )}
        {profile.file_default && <div className="muted small">{t('inspection.default')}</div>}
        <div className="muted small">{t('inspection.fileHelp')}</div>
      </label>
      {editable && (
        <div className="actions">
          <button type="submit" disabled={busy}>
            {t('common.save')}
          </button>
          {profile.configured && (
            <button type="button" className="secondary" disabled={busy} onClick={() => void call(() => api('/api/inspection-profile', 'DELETE'))}>
              {t('inspection.reset')}
            </button>
          )}
        </div>
      )}
    </form>
  );
}
