import { Navigate, Route, BrowserRouter as Router, Routes } from 'react-router-dom';

import { AppLayout } from '../layouts/AppLayout';
import { AlertsPage } from '../pages/AlertsPage';
import { AnalyticsPage } from '../pages/AnalyticsPage';
import { DashboardPage } from '../pages/DashboardPage';
import { FileAnalysisPage } from '../pages/FileAnalysisPage';
import { FileUploadPage } from '../pages/FileUploadPage';
import { LoginPage } from '../pages/LoginPage';
import { MalwareReportPage } from '../pages/MalwareReportPage';
import { ProfilePage } from '../pages/ProfilePage';
import { ThreatMonitoringPage } from '../pages/ThreatMonitoringPage';

export function AppRouter() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<AppLayout />}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/upload" element={<FileUploadPage />} />
          <Route path="/analysis" element={<FileAnalysisPage />} />
          <Route path="/malware-report" element={<MalwareReportPage />} />
          <Route path="/threat-monitoring" element={<ThreatMonitoringPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/analytics" element={<AnalyticsPage />} />
          <Route path="/profile" element={<ProfilePage />} />
        </Route>
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Router>
  );
}
