import { useState } from 'react';
import type { ComponentType, SyntheticEvent } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';

import type { FindingsPage, Permission, Snapshot } from '../api/types';
import { useAuth, useMe } from '../auth/AuthProvider';
import { useApi } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';
import type { MessageKey } from '../i18n/messages';
import {
  AdminIcon,
  AssetsIcon,
  BellIcon,
  ChevronRight,
  DevicesIcon,
  EventsIcon,
  FileIcon,
  InsightsIcon,
  LinkIcon,
  LogIcon,
  MenuIcon,
  ObjectsIcon,
  PlugIcon,
  ScoreIcon,
  SearchIcon,
  ShieldIcon,
  UserIcon,
  WrenchIcon,
} from './icons';

interface NavItem {
  to: string;
  label: MessageKey;
  icon: ComponentType<{ size?: number }>;
  permission: Permission | null;
  crumb: MessageKey[];
  end?: boolean;
}

interface NavGroup {
  heading: MessageKey;
  items: NavItem[];
}

/** Sidebar modelled on the current FMC: Monitor / Manage / Administration. */
const NAV: NavGroup[] = [
  {
    heading: 'shell.monitor',
    items: [
      { to: '/', label: 'nav.home', icon: InsightsIcon, permission: null, crumb: ['shell.monitor', 'nav.home'], end: true },
      { to: '/map', label: 'nav.map', icon: LinkIcon, permission: 'policy:read', crumb: ['shell.monitor', 'nav.map'] },
      { to: '/findings', label: 'nav.findings', icon: EventsIcon, permission: 'policy:read', crumb: ['shell.monitor', 'nav.findings'] },
      { to: '/scores', label: 'nav.scores', icon: ScoreIcon, permission: 'policy:read', crumb: ['shell.monitor', 'nav.scores'] },
      { to: '/recommendations', label: 'nav.recommendations', icon: WrenchIcon, permission: 'policy:read', crumb: ['shell.monitor', 'nav.recommendations'] },
    ],
  },
  {
    heading: 'shell.manage',
    items: [
      { to: '/policies', label: 'nav.policies', icon: ShieldIcon, permission: 'policy:read', crumb: ['nav.policies', 'shell.securityPolicies'] },
      { to: '/rules', label: 'nav.rules', icon: LogIcon, permission: 'policy:read', crumb: ['nav.policies', 'shell.securityPolicies', 'shell.policyEditor'] },
      { to: '/objects', label: 'nav.objects', icon: ObjectsIcon, permission: 'policy:read', crumb: ['nav.objects'] },
      { to: '/clusters', label: 'nav.clusters', icon: DevicesIcon, permission: 'policy:read', crumb: ['nav.clusters'] },
      { to: '/assets', label: 'nav.assets', icon: AssetsIcon, permission: 'policy:read', crumb: ['nav.assets'] },
      { to: '/snapshots', label: 'nav.snapshots', icon: PlugIcon, permission: 'policy:read', crumb: ['shell.integrations', 'nav.snapshots'] },
      { to: '/fmc', label: 'nav.fmc', icon: LinkIcon, permission: 'fmc:manage', crumb: ['shell.integrations', 'nav.fmc'] },
    ],
  },
  {
    heading: 'shell.administration',
    items: [
      { to: '/users', label: 'nav.users', icon: UserIcon, permission: 'users:manage', crumb: ['shell.administration', 'nav.users'] },
      { to: '/naming', label: 'nav.naming', icon: FileIcon, permission: 'policy:read', crumb: ['shell.administration', 'nav.naming'] },
      { to: '/audit', label: 'nav.audit', icon: EventsIcon, permission: 'audit:read', crumb: ['shell.administration', 'nav.audit'] },
      { to: '/settings', label: 'nav.settings', icon: AdminIcon, permission: null, crumb: ['shell.administration', 'nav.settings'] },
    ],
  },
];

function useBreadcrumb(): MessageKey[] {
  const { pathname } = useLocation();
  if (pathname.startsWith('/objects/')) return ['nav.objects', 'shell.objectDetail'];
  for (const group of NAV) {
    for (const item of group.items) {
      if (item.end === true ? pathname === item.to : pathname.startsWith(item.to)) return item.crumb;
    }
  }
  return ['nav.home'];
}

/** High-severity findings in the newest analysed snapshot (the bell badge). */
function useHighFindings(enabled: boolean): { count: number; snapshotId: number | null } {
  const snaps = useApi<Snapshot[]>(enabled ? '/api/snapshots?limit=20' : null);
  const latest = (snaps.data ?? []).find((s) => s.status === 'complete' && s.analyzed_at !== null);
  const page = useApi<FindingsPage>(
    latest === undefined ? null : `/api/snapshots/${String(latest.id)}/findings?severity=high&limit=1`,
  );
  return { count: page.data?.total ?? 0, snapshotId: latest?.id ?? null };
}

export function Layout() {
  const { t } = useI18n();
  const { can, logout } = useAuth();
  const me = useMe();
  const navigate = useNavigate();
  const crumb = useBreadcrumb();
  const [collapsed, setCollapsed] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [search, setSearch] = useState('');
  const readable = can('policy:read');
  const high = useHighFindings(readable);

  function onSearch(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const q = search.trim();
    if (q !== '') void navigate(`/objects?q=${encodeURIComponent(q)}`);
  }

  const alertsTarget =
    high.snapshotId === null ? '/findings' : `/findings?snapshot=${String(high.snapshotId)}&severity=high`;

  return (
    <div className={`fmc-shell${collapsed ? ' collapsed' : ''}`}>
      <header className="fmc-top">
        <button
          type="button"
          className="fmc-icon-btn fmc-hamburger"
          aria-label={t('shell.toggleMenu')}
          aria-expanded={!collapsed}
          onClick={() => {
            setCollapsed(!collapsed);
          }}
        >
          <MenuIcon />
        </button>
        <div className="fmc-brand">
          <div className="fmc-product">{t('app.title')}</div>
          <nav className="fmc-crumb" aria-label={t('shell.breadcrumb')}>
            {crumb.map((key, i) => (
              <span key={key} aria-current={i === crumb.length - 1 ? 'page' : undefined}>
                {t(key)}
              </span>
            ))}
          </nav>
        </div>
        <div className="fmc-top-actions">
          {readable && (
            <form className="fmc-search" role="search" onSubmit={onSearch}>
              <SearchIcon size={16} />
              <input
                type="search"
                dir="auto"
                maxLength={128}
                placeholder={t('shell.search')}
                aria-label={t('shell.search')}
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                }}
              />
            </form>
          )}
          {readable && (
            <button
              type="button"
              className="fmc-icon-btn"
              aria-label={t('shell.alerts', { count: high.count })}
              onClick={() => void navigate(alertsTarget)}
            >
              <BellIcon />
              {high.count > 0 && <span className="fmc-badge">{high.count > 99 ? '99+' : high.count}</span>}
            </button>
          )}
          <div className="fmc-user">
            <button
              type="button"
              className="fmc-user-btn"
              aria-haspopup="menu"
              aria-expanded={menuOpen}
              onClick={() => {
                setMenuOpen(!menuOpen);
              }}
            >
              <UserIcon size={16} />
              <bdi>{me.display_name || me.username}</bdi>
            </button>
            {menuOpen && (
              <div className="fmc-menu" role="menu">
                <NavLink
                  role="menuitem"
                  to="/settings"
                  onClick={() => {
                    setMenuOpen(false);
                  }}
                >
                  {t('nav.settings')}
                </NavLink>
                <NavLink
                  role="menuitem"
                  to="/password"
                  onClick={() => {
                    setMenuOpen(false);
                  }}
                >
                  {t('password.title')}
                </NavLink>
                <button type="button" role="menuitem" onClick={() => void logout()}>
                  {t('nav.logout')}
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      <nav className="fmc-side" aria-label={t('shell.mainMenu')}>
        {NAV.map((group) => {
          const items = group.items.filter((i) => i.permission === null || can(i.permission));
          if (items.length === 0) return null;
          return (
            <div key={group.heading} className="fmc-side-group">
              <div className="fmc-side-heading">{t(group.heading)}</div>
              {items.map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink key={item.to} to={item.to} end={item.end === true} title={t(item.label)}>
                    <Icon />
                    <span className="label">{t(item.label)}</span>
                    <ChevronRight size={14} className="chev" />
                  </NavLink>
                );
              })}
            </div>
          );
        })}
      </nav>

      <main className="fmc-main">
        <Outlet />
      </main>
    </div>
  );
}
