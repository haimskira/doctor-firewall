import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { api, errorCode } from '../api/client';
import type { AuditVerify, FmcConnection } from '../api/types';
import { useAuth, useMe } from '../auth/AuthProvider';
import { Alert, DateTime, Ltr } from '../components/common';
import { useI18n } from '../i18n/I18nProvider';

export function HomePage() {
  const { t, tError } = useI18n();
  const { can } = useAuth();
  const me = useMe();
  const [connections, setConnections] = useState<FmcConnection[] | null>(null);
  const [verify, setVerify] = useState<AuditVerify | null>(null);
  const [error, setError] = useState<string | null>(null);
  const canFmc = can('fmc:manage');

  useEffect(() => {
    if (!canFmc) return;
    api<FmcConnection[]>('/api/fmc/connections')
      .then(setConnections)
      .catch((err: unknown) => {
        setError(tError(errorCode(err)));
      });
  }, [canFmc, tError]);

  async function runVerify() {
    setError(null);
    try {
      setVerify(await api<AuditVerify>('/api/audit/verify', 'POST'));
    } catch (err: unknown) {
      setError(tError(errorCode(err)));
    }
  }

  return (
    <div className="stack">
      <h1>{t('home.welcome', { name: me.display_name || me.username })}</h1>
      {error !== null && <Alert kind="error">{error}</Alert>}

      <section className="card">
        <h2>{t('home.roles')}</h2>
        <ul className="chips">
          {me.roles.map((role) => (
            <li key={role} className="chip">
              {t(`role.${role}`)}
            </li>
          ))}
        </ul>
        <h2>{t('home.permissions')}</h2>
        <ul>
          {me.permissions.map((perm) => (
            <li key={perm}>{t(`perm.${perm}`)}</li>
          ))}
        </ul>
      </section>

      {canFmc && (
        <section className="card">
          <h2>{t('home.fmcStatus')}</h2>
          {connections === null && <p className="muted">{t('common.loading')}</p>}
          {connections?.length === 0 && (
            <p>
              {t('home.fmcNone')} <Link to="/fmc">{t('fmc.add')}</Link>
            </p>
          )}
          {connections?.map((c) => (
            <p key={c.id}>
              <strong>{c.name}</strong> —{' '}
              <Ltr>
                {c.host}:{c.port}
              </Ltr>{' '}
              · {t('fmc.lastTest')}: <DateTime value={c.last_test_at} />{' '}
              {c.last_test_ok === true && <span className="ok">✔</span>}
              {c.last_test_ok === false && <span className="bad">✘</span>}
            </p>
          ))}
        </section>
      )}

      {can('audit:read') && (
        <section className="card">
          <h2>{t('home.auditStatus')}</h2>
          <button type="button" onClick={() => void runVerify()}>
            {t('home.auditVerify')}
          </button>
          {verify?.ok === true && (
            <Alert kind="success">{t('audit.verifyOk', { count: verify.checked })}</Alert>
          )}
          {verify?.ok === false && (
            <Alert kind="error">
              {t('audit.verifyBroken', {
                id: verify.broken_at_id ?? '?',
                reason: verify.reason ?? '?',
              })}
            </Alert>
          )}
        </section>
      )}
    </div>
  );
}
