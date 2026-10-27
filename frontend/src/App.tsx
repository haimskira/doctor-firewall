import { Navigate, Route, Routes } from 'react-router-dom';
import type { ReactNode } from 'react';

import type { Permission } from './api/types';
import { useAuth } from './auth/AuthProvider';
import { Layout } from './components/Layout';
import { useI18n } from './i18n/I18nProvider';
import { AssetsPage } from './pages/AssetsPage';
import { AttackSurfacePage } from './pages/AttackSurfacePage';
import { JobsPage } from './pages/JobsPage';
import { AuditPage } from './pages/AuditPage';
import { DeployPage } from './pages/DeployPage';
import { ChangePasswordPage } from './pages/ChangePasswordPage';
import { ClustersPage } from './pages/ClustersPage';
import { FindingsPage } from './pages/FindingsPage';
import { FmcPage } from './pages/FmcPage';
import { HomePage } from './pages/HomePage';
import { LoginPage } from './pages/LoginPage';
import { MapPage } from './pages/MapPage';
import { InspectionPage } from './pages/InspectionPage';
import { NamingPage } from './pages/NamingPage';
import { ObjectDetailPage } from './pages/ObjectDetailPage';
import { ObjectExplorerPage } from './pages/ObjectExplorerPage';
import { ObjectsPage } from './pages/ObjectsPage';
import { PoliciesPage } from './pages/PoliciesPage';
import { RecommendationsPage } from './pages/RecommendationsPage';
import { RulebasePage } from './pages/RulebasePage';
import { ScoresPage } from './pages/ScoresPage';
import { SettingsPage } from './pages/SettingsPage';
import { SnapshotsPage } from './pages/SnapshotsPage';
import { UsersPage } from './pages/UsersPage';

/** UI-side gate only (hides pages); the server enforces every permission itself. */
function RequirePermission({ permission, children }: { permission: Permission; children: ReactNode }) {
  const { can } = useAuth();
  return can(permission) ? <>{children}</> : <Navigate to="/" replace />;
}

export function App() {
  const { state } = useAuth();
  const { t } = useI18n();

  if (state.status === 'loading') {
    return <p className="center-page muted">{t('common.loading')}</p>;
  }
  if (state.status === 'anonymous') {
    return <LoginPage />;
  }
  if (state.me.must_change_password) {
    return (
      <div className="center-page">
        <ChangePasswordPage />
      </div>
    );
  }
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<HomePage />} />
        {(
          [
            ['snapshots', <SnapshotsPage key="s" />],
            ['clusters', <ClustersPage key="c" />],
            ['policies', <PoliciesPage key="p" />],
            ['rules', <RulebasePage key="r" />],
            ['objects', <ObjectsPage key="o" />],
            ['objects/explore', <ObjectExplorerPage key="x" />],
            ['objects/:objectId', <ObjectDetailPage key="d" />],
            ['findings', <FindingsPage key="f" />],
            ['scores', <ScoresPage key="q" />],
            ['assets', <AssetsPage key="a" />],
            ['recommendations', <RecommendationsPage key="m" />],
            ['map', <MapPage key="g" />],
            ['attack', <AttackSurfacePage key="t" />],
            ['jobs', <JobsPage key="j" />],
            ['deploy', <DeployPage key="y" />],
            ['naming', <NamingPage key="n" />],
            ['inspection', <InspectionPage key="i" />],
          ] as const
        ).map(([path, element]) => (
          <Route key={path} path={path} element={<RequirePermission permission="policy:read">{element}</RequirePermission>} />
        ))}
        <Route
          path="users"
          element={
            <RequirePermission permission="users:manage">
              <UsersPage />
            </RequirePermission>
          }
        />
        <Route
          path="fmc"
          element={
            <RequirePermission permission="fmc:manage">
              <FmcPage />
            </RequirePermission>
          }
        />
        <Route
          path="audit"
          element={
            <RequirePermission permission="audit:read">
              <AuditPage />
            </RequirePermission>
          }
        />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="password" element={<ChangePasswordPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
