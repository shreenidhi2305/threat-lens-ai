import { Navigate, Route, BrowserRouter as Router, Routes } from 'react-router-dom';
import type { ReactNode } from 'react';

import { useAuth } from '../auth/AuthContext';
import { AppLayout } from '../layouts/AppLayout';
import { AlertsPage } from '../pages/AlertsPage';
import { AnalyticsPage } from '../pages/AnalyticsPage';
import { DashboardPage } from '../pages/DashboardPage';
import { LoginPage } from '../pages/LoginPage';
import { ProfilePage } from '../pages/ProfilePage';
import { ReportPage } from '../pages/ReportPage';
import { SubmitPage } from '../pages/SubmitPage';
import { ThreatsPage } from '../pages/ThreatsPage';
import { Spinner } from '../ui/primitives';

function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="grid min-h-screen place-items-center bg-bg">
        <Spinner />
      </div>
    );
  }
  return user ? <>{children}</> : <Navigate to="/login" replace />;
}

export function AppRouter() {
  return (
    <Router>
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
          <Route path="/threats" element={<ThreatsPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/analytics" element={<AnalyticsPage />} />
          <Route path="/profile" element={<ProfilePage />} />
        </Route>
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Router>
  );
}
