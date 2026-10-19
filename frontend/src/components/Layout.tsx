import { NavLink, Outlet } from 'react-router-dom';

import { useAuth, useMe } from '../auth/AuthProvider';
import { useI18n } from '../i18n/I18nProvider';

export function Layout() {
  const { t } = useI18n();
  const { can, logout } = useAuth();
  const me = useMe();

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <strong>{t('app.title')}</strong>
          <span className="muted">{t('app.tagline')}</span>
        </div>
        <nav aria-label="main">
          <NavLink to="/" end>
            {t('nav.home')}
          </NavLink>
          {can('users:manage') && <NavLink to="/users">{t('nav.users')}</NavLink>}
          {can('fmc:manage') && <NavLink to="/fmc">{t('nav.fmc')}</NavLink>}
          {can('audit:read') && <NavLink to="/audit">{t('nav.audit')}</NavLink>}
          <NavLink to="/settings">{t('nav.settings')}</NavLink>
        </nav>
        <div className="user">
          <span>{me.display_name || me.username}</span>
          <button type="button" className="link" onClick={() => void logout()}>
            {t('nav.logout')}
          </button>
        </div>
      </header>
      <main>
        <Outlet />
      </main>
    </div>
  );
}
