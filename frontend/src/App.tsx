import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import MainLayout from './components/layout/MainLayout';
import ProtectedRoute from './components/ProtectedRoute';
import Login from './pages/Login';
import Dashboard from './pages/DashboardOverview';
import History from './pages/History';
import PromptLibrary from './pages/PromptLibrary';
import Settings from './pages/Settings';
import ThreatModeling from './pages/ThreatModeling';
import AttackGraphPage from './pages/AttackGraphPage';
import DetectionEngineering from './pages/DetectionEngineering';
import DefenseSimulation from './pages/DefenseSimulation';
import ThreatIntelligence from './pages/ThreatIntelligence';
import CollectiveDefense from './pages/CollectiveDefense';
import ResearchMetrics from './pages/ResearchMetrics';
import About from './pages/About';
import KnowledgeGraph from './pages/KnowledgeGraph';
import Benchmark from './pages/Benchmark';

/**
 * Entry point routing aplikasi React.
 */
export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />

        <Route element={<ProtectedRoute />}>
          <Route path="/" element={<MainLayout />}>
            <Route index element={<Dashboard />} />
            <Route path="threat-modeling" element={<ThreatModeling />} />
            <Route path="attack-graph" element={<AttackGraphPage />} />
            <Route path="knowledge-graph" element={<KnowledgeGraph />} />
            <Route path="detection" element={<DetectionEngineering />} />
            <Route path="simulation" element={<DefenseSimulation />} />
            <Route path="intelligence" element={<ThreatIntelligence />} />
            <Route path="collective-defense" element={<CollectiveDefense />} />
            <Route path="research" element={<ResearchMetrics />} />
            <Route path="benchmark" element={<Benchmark />} />
            <Route path="history" element={<History />} />
            <Route path="library" element={<PromptLibrary />} />
            <Route path="settings" element={<Settings />} />
            <Route path="about" element={<About />} />
          </Route>
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
