import {
  BellIcon,
  CaretDownIcon,
  CaretRightIcon,
  ChartLineIcon,
  CubeIcon,
  HardDrivesIcon,
  ListIcon,
  MagnifyingGlassIcon,
  MoonIcon,
  PlugsIcon,
  PulseIcon,
  ShieldCheckIcon,
  ShieldIcon,
  SunIcon,
  UserGearIcon,
} from '@phosphor-icons/react';
import type { Icon } from '@phosphor-icons/react';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { RefObject, SyntheticEvent } from 'react';
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';

import { api } from '../api/client';
import { ErrorBoundary } from './ErrorBoundary';
import type { FindingsPage, Me, Permission, Snapshot } from '../api/types';
import { applyTheme, effectiveTheme, useAuth, useMe } from '../auth/AuthProvider';
import { useApi } from '../hooks';
import { useI18n } from '../i18n/I18nProvider';
import type { MessageKey } from '../i18n/messages';

interface NavLeaf {
  to: string;
  label: MessageKey;
  permission: Permission | null;
  end?: boolean;
}

interface NavItem {
  id: string;
  label: MessageKey;
  icon: Icon;
  children: NavLeaf[];
}

interface NavGroup {
  heading: MessageKey | null;
  items: NavItem[];
}

/** The current FMC navigation: Monitor / Manage, then Administration below a divider. */
const NAV: NavGroup[] = [
  {
    heading: 'shell.monitor',
    items: [
      {
        id: 'insights',
        label: 'shell.insights',
        icon: ChartLineIcon,
        children: [
          { to: '/', label: 'nav.dashboard', permission: null, end: true },
          { to: '/map', label: 'nav.map', permission: 'policy:read' },
          { to: '/attack', label: 'nav.attack', permission: 'policy:read' },
          { to: '/scores', label: 'nav.scores', permission: 'policy:read' },
        ],
      },
      {
        id: 'events',
        label: 'shell.events',
        icon: PulseIcon,
        children: [
          { to: '/findings', label: 'nav.findings', permission: 'policy:read' },
          { to: '/audit', label: 'nav.audit', permission: 'audit:read' },
        ],
      },
    ],
  },
  {
    heading: 'shell.manage',
    items: [
      {
        id: 'policies',
        label: 'nav.policies',
        icon: ShieldIcon,
        children: [
          { to: '/rules', label: 'shell.policyEditor', permission: 'policy:read' },
          { to: '/policies', label: 'shell.securityPolicies', permission: 'policy:read' },
          { to: '/recommendations', label: 'nav.recommendations', permission: 'policy:read' },
          { to: '/naming', label: 'nav.naming', permission: 'policy:read' },
          { to: '/inspection', label: 'nav.inspection', permission: 'policy:read' },
          { to: '/deploy', label: 'nav.deploy', permission: 'policy:read' },
        ],
      },
      {
        id: 'objects',
        label: 'nav.objects',
        icon: CubeIcon,
        children: [
          { to: '/objects', label: 'shell.objectManagement', permission: 'policy:read' },
          { to: '/objects/explore', label: 'nav.explorer', permission: 'policy:read' },
          { to: '/assets', label: 'nav.assets', permission: 'policy:read' },
        ],
      },
      {
        id: 'devices',
        label: 'shell.devices',
        icon: HardDrivesIcon,
        children: [{ to: '/clusters', label: 'nav.clusters', permission: 'policy:read' }],
      },
      {
        id: 'integrations',
        label: 'shell.integrations',
        icon: PlugsIcon,
        children: [
          { to: '/fmc', label: 'nav.fmc', permission: 'fmc:manage' },
          { to: '/snapshots', label: 'nav.snapshots', permission: 'policy:read' },
        ],
      },
    ],
  },
  {
    heading: null,
    items: [
      {
        id: 'administration',
        label: 'shell.administration',
        icon: UserGearIcon,
        children: [
          { to: '/users', label: 'nav.users', permission: 'users:manage' },
          { to: '/settings', label: 'nav.settings', permission: null },
          { to: '/password', label: 'password.title', permission: null },
        ],
      },
    ],
  },
];

function matches(leaf: NavLeaf, pathname: string): boolean {
  if (leaf.end === true) return pathname === leaf.to;
  return pathname === leaf.to || pathname.startsWith(`${leaf.to}/`);
}

function useBreadcrumb(): MessageKey[] {
  const { pathname } = useLocation();
  if (pathname.startsWith('/objects/')) return ['nav.objects', 'shell.objectDetail'];
  for (const group of NAV) {
    for (const item of group.items) {
      const leaf = item.children.find((c) => matches(c, pathname));
      if (leaf !== undefined) return item.children.length > 1 ? [item.label, leaf.label] : [item.label];
    }
  }
  return ['nav.dashboard'];
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

/** Close a popup on an outside click or Escape. */
function useDismiss(open: boolean, close: () => void, ref: RefObject<HTMLElement | null>) {
  useEffect(() => {
    if (!open) return undefined;
    function onPointer(event: MouseEvent) {
      if (ref.current !== null && event.target instanceof Node && !ref.current.contains(event.target)) close();
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === 'Escape') close();
    }
    document.addEventListener('mousedown', onPointer);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onPointer);
      document.removeEventListener('keydown', onKey);
    };
  }, [open, close, ref]);
}

export function Layout() {
  const { t } = useI18n();
  const { can, logout, state } = useAuth();
  // Directory accounts (LDAP / TACACS+) change their password in the directory, not here.
  const localAccount = state.status === 'authenticated' && state.me.auth_provider === 'local';
  const me = useMe();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const crumb = useBreadcrumb();
  const [collapsed, setCollapsed] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [flyout, setFlyout] = useState<{ id: string; path: string } | null>(null);
  const [search, setSearch] = useState('');
  const readable = can('policy:read');
  const high = useHighFindings(readable);
  const sideRef = useRef<HTMLElement>(null);
  const userRef = useRef<HTMLDivElement>(null);
  const closeFlyout = useCallback(() => {
    setFlyout(null);
  }, []);
  const closeMenu = useCallback(() => {
    setMenuOpen(false);
  }, []);
  // A flyout belongs to the page it was opened on: navigating closes it.
  const openFlyout = flyout !== null && flyout.path === pathname ? flyout.id : null;
  useDismiss(openFlyout !== null, closeFlyout, sideRef);
  useDismiss(menuOpen, closeMenu, userRef);

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
        <Link to="/" className="fmc-brand" aria-label={t('app.title')}>
          <ShieldCheckIcon size={26} weight="duotone" aria-hidden="true" className="fmc-logo" />
          <span className="fmc-brand-text">
            <span className="fmc-product">{t('app.title')}</span>
            <span className="fmc-crumb">
              {crumb.map((key, i) => (
                <span key={key} aria-current={i === crumb.length - 1 ? 'page' : undefined}>
                  {t(key)}
                </span>
              ))}
            </span>
          </span>
        </Link>
        <div className="fmc-top-actions">
          {readable && (
            <form className="fmc-search" role="search" onSubmit={onSearch}>
              <MagnifyingGlassIcon size={16} aria-hidden="true" />
              <input
                type="search"
                dir="auto"
                maxLength={128}
                placeholder={t('common.search')}
                aria-label={t('shell.search')}
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                }}
              />
            </form>
          )}
          {readable && (
            <NavLink to="/deploy" className="fmc-deploy">
              {t('shell.deploy')}
            </NavLink>
          )}
          {readable && (
            <button
              type="button"
              className="fmc-icon-btn"
              aria-label={t('shell.alerts', { count: high.count })}
              onClick={() => void navigate(alertsTarget)}
            >
              <BellIcon size={19} aria-hidden="true" />
              {high.count > 0 && (
                <bdi dir="ltr" className="fmc-badge">
                  {high.count > 99 ? '99+' : high.count}
                </bdi>
              )}
            </button>
          )}
          <ThemeToggle />
          <span className="fmc-top-divider" aria-hidden="true" />
          <div className="fmc-user" ref={userRef}>
            <button
              type="button"
              className="fmc-user-btn"
              aria-haspopup="menu"
              aria-expanded={menuOpen}
              onClick={() => {
                setMenuOpen(!menuOpen);
              }}
            >
              <bdi>{me.display_name || me.username}</bdi>
              <CaretDownIcon size={14} aria-hidden="true" />
            </button>
            {menuOpen && (
              <div className="fmc-menu" role="menu">
                <NavLink role="menuitem" to="/settings" onClick={closeMenu}>
                  {t('nav.settings')}
                </NavLink>
                <NavLink role="menuitem" to="/password" onClick={closeMenu}>
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

      <nav className="fmc-side" aria-label={t('shell.mainMenu')} ref={sideRef}>
        <button
          type="button"
          className="fmc-hamburger"
          aria-label={t('shell.toggleMenu')}
          aria-expanded={!collapsed}
          onClick={() => {
            setCollapsed(!collapsed);
          }}
        >
          <ListIcon size={20} aria-hidden="true" />
        </button>
        {NAV.map((group, gi) => {
          const items = group.items
            .map((item) => ({
              ...item,
              children: item.children.filter(
                (c) => (c.permission === null || can(c.permission)) && (c.to !== '/password' || localAccount),
              ),
            }))
            .filter((item) => item.children.length > 0);
          if (items.length === 0) return null;
          return (
            <div key={group.heading ?? `g${String(gi)}`} className="fmc-side-group">
              {group.heading !== null && <div className="fmc-side-heading">{t(group.heading)}</div>}
              {items.map((item) => {
                const ItemIcon = item.icon;
                const active = item.children.some((c) => matches(c, pathname));
                const only = item.children.length === 1 ? item.children[0] : undefined;
                if (only !== undefined) {
                  return (
                    <NavLink key={item.id} to={only.to} end={only.end === true} className="fmc-side-item" title={t(item.label)}>
                      <ItemIcon size={20} aria-hidden="true" />
                      <span className="label">{t(item.label)}</span>
                    </NavLink>
                  );
                }
                const open = openFlyout === item.id;
                return (
                  <div key={item.id} className="fmc-side-entry">
                    <button
                      type="button"
                      className={`fmc-side-item${active ? ' active' : ''}${open ? ' open' : ''}`}
                      aria-haspopup="true"
                      aria-expanded={open}
                      title={t(item.label)}
                      onClick={() => {
                        setFlyout(open ? null : { id: item.id, path: pathname });
                      }}
                    >
                      <ItemIcon size={20} aria-hidden="true" />
                      <span className="label">{t(item.label)}</span>
                      <CaretRightIcon size={14} className="chev" aria-hidden="true" />
                    </button>
                    {open && (
                      <div className="fmc-flyout" role="menu" aria-label={t(item.label)}>
                        <div className="fmc-flyout-title">{t(item.label)}</div>
                        {item.children.map((leaf) => (
                          <NavLink key={leaf.to} to={leaf.to} end={leaf.end === true} role="menuitem">
                            {t(leaf.label)}
                          </NavLink>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          );
        })}
      </nav>

      <main className="fmc-main">
        <ErrorBoundary key={pathname} message={t('error.page')} retry={t('error.retry')}>
          <Outlet />
        </ErrorBoundary>
      </main>
    </div>
  );
}

/** Light / dark switch in the top bar; the choice is saved with the user's preferences. */
function ThemeToggle() {
  const { t } = useI18n();
  const { state, setMe } = useAuth();
  if (state.status !== 'authenticated') return null;
  const current = effectiveTheme(state.me.theme);
  const next = current === 'dark' ? 'light' : 'dark';
  const label = t(next === 'dark' ? 'settings.theme.toDark' : 'settings.theme.toLight');
  return (
    <button
      type="button"
      className="fmc-icon-btn fmc-theme-btn"
      aria-label={label}
      title={label}
      onClick={() => {
        applyTheme(next);
        void api<Me>('/api/me/preferences', 'PATCH', { theme: next }).then(setMe, () => {
          applyTheme(state.me.theme);
        });
      }}
    >
      {current === 'dark' ? <SunIcon size={19} aria-hidden="true" /> : <MoonIcon size={19} aria-hidden="true" />}
    </button>
  );
}
