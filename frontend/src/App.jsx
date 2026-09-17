/**
 * =============================================================================
 * AETHER ARAN IAM - MAIN APPLICATION ROOT (WITH COGNITO AUTH GUARD)
 * =============================================================================
 * 
 * Simple Explanation (Zero-Coding Background):
 * - Auth Guard: If the user is NOT logged in, they see the Cyberpunk Login or Sign Up page.
 * - In-Memory State: Once authenticated via AWS Cognito, the token is stored in React memory,
 *   and the user enters the full SOC dashboard.
 * =============================================================================
 */

import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import LoginPage from './pages/LoginPage';
import SignupPage from './pages/SignupPage';
import SideNavBar from './components/SideNavBar';
import TopNavBar from './components/TopNavBar';
import OverviewPage from './pages/OverviewPage';
import DriftAnalyzerPage from './pages/DriftAnalyzerPage';
import CredentialHygienePage from './pages/CredentialHygienePage';
import AiAssistantPage from './pages/AiAssistantPage';
import ScanHistoryPage from './pages/ScanHistoryPage';
import { initializeScan } from './services/api';

function Dashboard() {
  const [activeTab, setActiveTab] = useState('overview');
  const [searchTerm, setSearchTerm] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState(new Date());
  const [mobileOpen, setMobileOpen] = useState(false);
  const [initialAssistantQuery, setInitialAssistantQuery] = useState('');

  const handleScan = async () => {
    setIsScanning(true);
    try {
      await initializeScan();
    } catch (err) {
      console.warn('Initialize scan note:', err);
    } finally {
      setIsScanning(false);
      setLastRefreshed(new Date());
    }
  };

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => {
      setIsRefreshing(false);
      setLastRefreshed(new Date());
    }, 800);
  };

  const handleNavigateToAssistant = (query) => {
    setInitialAssistantQuery(query);
    setActiveTab('assistant');
  };

  const lastRefreshedText = `Last Refreshed: ${lastRefreshed.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })}`;

  return (
    <div className="bg-background text-on-surface antialiased min-h-screen flex relative selection:bg-primary-container selection:text-on-primary-container">
      {/* Global Atmospheric CRT Scanlines Overlay */}
      <div className="fixed inset-0 cyber-scan-lines pointer-events-none opacity-20 z-50"></div>

      {/* Side Navigation Bar (Fixed Left on desktop, slide drawer on mobile) */}
      <SideNavBar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onScanClick={handleScan}
        isScanning={isScanning}
        mobileOpen={mobileOpen}
        setMobileOpen={setMobileOpen}
      />

      {/* Main Content Area */}
      <div className="flex-1 md:ml-72 flex flex-col min-h-screen relative z-30">
        {/* Top Header */}
        <TopNavBar
          searchTerm={searchTerm}
          setSearchTerm={setSearchTerm}
          onRefresh={handleRefresh}
          isRefreshing={isRefreshing}
          lastRefreshedText={lastRefreshedText}
          onOpenMobileMenu={() => setMobileOpen(true)}
        />

        {/* Dynamic Page Router Canvas */}
        <main className="flex-1 p-4 sm:p-6 md:p-8 max-w-[1800px] w-full mx-auto">
          <div key={activeTab} className="animate-tab-enter">
            {activeTab === 'overview' && (
              <OverviewPage
                searchTerm={searchTerm}
                key={lastRefreshed.getTime()}
                onNavigateToAssistant={handleNavigateToAssistant}
              />
            )}
            {activeTab === 'drift' && (
              <DriftAnalyzerPage
                searchTerm={searchTerm}
                key={lastRefreshed.getTime()}
                onNavigateToAssistant={handleNavigateToAssistant}
              />
            )}
            {activeTab === 'hygiene' && (
              <CredentialHygienePage
                searchTerm={searchTerm}
                key={lastRefreshed.getTime()}
                onNavigateToAssistant={handleNavigateToAssistant}
              />
            )}
            {activeTab === 'assistant' && (
              <AiAssistantPage
                initialQuery={initialAssistantQuery}
                key={initialAssistantQuery || 'assistant'}
              />
            )}
            {activeTab === 'history' && (
              <ScanHistoryPage
                searchTerm={searchTerm}
                key={lastRefreshed.getTime()}
                onNavigateToAssistant={handleNavigateToAssistant}
              />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}

function MainAppContent() {
  const { isAuthenticated } = useAuth();
  const [authView, setAuthView] = useState('login'); // 'login' | 'signup'

  // If user is authenticated via AWS Cognito, display the protected SOC dashboard
  if (isAuthenticated) {
    return <Dashboard />;
  }

  // Otherwise, display the Login or Sign Up screen
  if (authView === 'signup') {
    return <SignupPage onNavigateToLogin={() => setAuthView('login')} />;
  }

  return <LoginPage onNavigateToSignup={() => setAuthView('signup')} />;
}

export default function App() {
  return (
    <AuthProvider>
      <MainAppContent />
    </AuthProvider>
  );
}
