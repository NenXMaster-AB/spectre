/**
 * SPECTRE Web Application
 *
 * Main application component with routing setup.
 */

import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AppLayout } from './components/layout';
import {
  Dashboard,
  Investigations,
  Entities,
  ThreatActors,
  Reports,
  Plugins,
  Settings,
} from './pages';

// Create a client for React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      retry: 1,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<AppLayout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/investigations" element={<Investigations />} />
            <Route path="/entities" element={<Entities />} />
            <Route path="/threat-actors" element={<ThreatActors />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/plugins" element={<Plugins />} />
            <Route path="/settings" element={<Settings />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
