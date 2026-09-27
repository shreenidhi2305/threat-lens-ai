import { AnalysisProvider } from './analysis/AnalysisStore';
import { AuthProvider } from './auth/AuthContext';
import { AppRouter } from './routes/AppRouter';

function App() {
  return (
    <AuthProvider>
      <AnalysisProvider>
        <AppRouter />
      </AnalysisProvider>
    </AuthProvider>
  );
}

export default App;
