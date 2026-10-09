import { Suspense, lazy } from 'react';
import { Navigate, Route, BrowserRouter as Router, Routes } from 'react-router-dom';
import type { ReactNode } from 'react';

import { useAuth } from '../auth/AuthContext';
import { AppLayout } from '../layouts/AppLayout';
import { Spinner } from '../ui/primitives';

// Each page is its own chunk, so the first paint only downloads the shell plus the
// page being opened instead of the whole app.
const AlertsPage = lazy(() => import('../pages/AlertsPage').then((m) => ({ default: m.AlertsPage })));
const AnalyticsPage = lazy(() =>
  import('../pages/AnalyticsPage').then((m) => ({ default: m.AnalyticsPage })),
);
const BehaviorPage = lazy(() =>
  import('../pages/BehaviorPage').then((m) => ({ default: m.BehaviorPage })),
);
const DashboardPage = lazy(() =>
  import('../pages/DashboardPage').then((m) => ({ default: m.DashboardPage })),
);
const LoginPage = lazy(() => import('../pages/LoginPage').then((m) => ({ default: m.LoginPage })));
const ProfilePage = lazy(() =>
  import('../pages/ProfilePage').then((m) => ({ default: m.ProfilePage })),
);
const ReportPage = lazy(() => import('../pages/ReportPage').then((m) => ({ default: m.ReportPage })));
const SubmitPage = lazy(() => import('../pages/SubmitPage').then((m) => ({ default: m.SubmitPage })));
const ThreatsPage = lazy(() =>
  import('../pages/ThreatsPage').then((m) => ({ default: m.ThreatsPage })),
);

function FullScreenSpinner() {
  return (
    <div className="grid min-h-dvh place-items-center bg-bg">
      <Spinner />
    </div>
  );
}

function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <FullScreenSpinner />;
  return user ? <>{children}</> : <Navigate to="/login" replace />;
}

export function AppRouter() {
  return (
    <Router>
      <Suspense fallback={<FullScreenSpinner />}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            element={
              <RequireAuth>
                <AppLayout />
              </RequireAuth>
            }
          >
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/submit" element={<SubmitPage />} />
            <Route path="/reports" element={<ReportPage />} />
            <Route path="/behavior" element={<BehaviorPage />} />
            <Route path="/threats" element={<ThreatsPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
            <Route path="/profile" element={<ProfilePage />} />
          </Route>
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Suspense>
    </Router>
  );
}
