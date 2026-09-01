import { Navigate, Route, BrowserRouter as Router, Routes } from 'react-router-dom';
import type { ReactNode } from 'react';

import { useAuth } from '../auth/AuthContext';
import { AppLayout } from '../layouts/AppLayout';
import { ComingSoonPage } from '../pages/ComingSoonPage';
import { DashboardPage } from '../pages/DashboardPage';
import { FileAnalysisPage } from '../pages/FileAnalysisPage';
import { FileUploadPage } from '../pages/FileUploadPage';
import { LoginPage } from '../pages/LoginPage';
import { ProfilePage } from '../pages/ProfilePage';

function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) {
    return <div className="p-10 text-slate-400">Loading…</div>;
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
          <Route path="/upload" element={<FileUploadPage />} />
          <Route path="/analysis" element={<FileAnalysisPage />} />
          <Route
            path="/malware-report"
            element={<ComingSoonPage title="Malware Report" milestone={2} />}
          />
          <Route
            path="/threat-monitoring"
            element={<ComingSoonPage title="Threat Monitoring" milestone={2} />}
          />
          <Route path="/alerts" element={<ComingSoonPage title="Alerts" milestone={2} />} />
          <Route path="/analytics" element={<ComingSoonPage title="Analytics" milestone={3} />} />
          <Route path="/profile" element={<ProfilePage />} />
        </Route>
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Router>
  );
}
