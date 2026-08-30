import React from 'react';

export default function SideNavBar({
  activeTab,
  setActiveTab,
  onScanClick,
  isScanning,
  mobileOpen,
  setMobileOpen,
}) {
  const navItems = [
    {
      id: 'overview',
      label: 'Privilege Escalation',
      icon: 'security',
      description: 'Threat Telemetry & Risk Findings',
    },
    {
      id: 'drift',
      label: 'Privilege Drift',
      icon: 'trending_down',
      description: 'Least-Privilege Gap Analysis',
    },
    {
      id: 'hygiene',
      label: 'Credential Hygiene',
      icon: 'password',
      description: 'MFA & Key Rotation Posture',
    },
    {
      id: 'assistant',
      label: 'AI Assistant',
      icon: 'auto_awesome',
      description: 'NIMORA Cyber-Ops',
    },
    {
      id: 'history',
      label: 'Scan History',
      icon: 'history_toggle_off',
      description: 'DynamoDB Telemetry & Audit Logs',
    },
  ];

  const handleSelectTab = (id) => {
    setActiveTab(id);
    if (setMobileOpen) setMobileOpen(false);
  };

  return (
    <>
      {/* Mobile Backdrop Overlay */}
      {mobileOpen && (
        <div
          onClick={() => setMobileOpen(false)}
          className="fixed inset-0 bg-black/80 z-40 md:hidden backdrop-blur-sm transition-opacity"
        />
      )}

      {/* Main Sidebar (Desktop fixed left, Mobile sliding drawer) */}
      <nav
        className={`h-screen w-72 fixed left-0 top-0 bg-surface-container-lowest/90 backdrop-blur-2xl border-r border-outline-variant/30 shadow-[5px_0_25px_rgba(0,0,0,0.8)] flex flex-col py-6 z-50 select-none transition-transform duration-300 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
        }`}
      >
        {/* Brand Header */}
        <div className="px-6 mb-8 flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded bg-surface-variant flex items-center justify-center border border-primary-fixed/50 shadow-[0_0_12px_rgba(190,245,0,0.3)] relative overflow-hidden shrink-0">
              <span className="material-symbols-outlined text-primary-fixed text-2xl">
                shield_with_heart
              </span>
            </div>
            <div>
              <h2 className="font-metric-md text-2xl text-primary-fixed leading-none tracking-wider font-normal">
                AETHER ARAN
              </h2>
              <span className="font-label-caps text-[10px] text-on-surface-variant uppercase tracking-wider block mt-0.5 opacity-90">
                by Pluma Security
              </span>
              <span className="font-label-caps text-[11px] text-secondary leading-none mt-1.5 block tracking-widest flex items-center gap-1.5 font-bold">
                <span className="w-2 h-2 rounded-full bg-[#FF2E9F] animate-pulse"></span>
                Threat Level: High
              </span>
            </div>
          </div>

          {/* Close button on mobile */}
          <button
            onClick={() => setMobileOpen(false)}
            className="md:hidden p-1 text-on-surface-variant hover:text-primary"
          >
            <span className="material-symbols-outlined text-xl">close</span>
          </button>
        </div>

        {/* Navigation Links */}
        <div className="flex-1 px-4 space-y-2">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => handleSelectTab(item.id)}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded text-left transition-all duration-200 group ${
                  isActive
                    ? 'bg-primary-container text-on-primary-container border-l-4 border-primary-fixed shadow-[0_0_15px_rgba(166,215,0,0.35)] font-bold'
                    : 'text-on-surface-variant opacity-70 hover:bg-surface-container-high hover:opacity-100 hover:translate-x-1'
                }`}
              >
                <span
                  className="material-symbols-outlined text-xl"
                  style={{
                    fontVariationSettings: isActive ? "'FILL' 1" : "'FILL' 0",
                  }}
                >
                  {item.icon}
                </span>
                <span className="font-label-caps text-label-caps uppercase tracking-wider text-xs">
                  {item.label}
                </span>
              </button>
            );
          })}
        </div>

        {/* Initialize Scan & Footer */}
        <div className="px-4 mt-auto space-y-4">
          <button
            onClick={onScanClick}
            disabled={isScanning}
            className="w-full py-3 px-4 border border-primary-fixed/60 text-primary-fixed font-label-caps text-xs uppercase tracking-widest hover:bg-primary-fixed hover:text-on-primary-fixed transition-all duration-300 rounded relative overflow-hidden group flex items-center justify-center gap-2 glow-lime disabled:opacity-50 font-bold"
          >
            <span
              className={`material-symbols-outlined text-base ${
                isScanning ? 'animate-spin' : 'group-hover:rotate-45 transition-transform'
              }`}
            >
              radar
            </span>
            <span>{isScanning ? 'Scanning Telemetry...' : 'Initialize Scan'}</span>
          </button>

          <div className="pt-4 border-t border-outline-variant/20 flex flex-col gap-1 text-on-surface-variant text-xs">
            <a
              href="http://127.0.0.1:8000/docs"
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-2 px-2 py-1.5 opacity-70 hover:opacity-100 hover:text-primary-fixed transition-colors font-label-caps uppercase text-[11px]"
            >
              <span className="material-symbols-outlined text-sm">terminal</span>
              <span>FastAPI Docs (/docs)</span>
            </a>
            <div className="flex items-center gap-2 px-2 py-1.5 opacity-70 font-label-caps uppercase text-[11px]">
              <span className="w-1.5 h-1.5 rounded-full bg-primary-fixed animate-pulse"></span>
              <span>Engine: NIMORA v1.0</span>
            </div>
          </div>
        </div>
      </nav>
    </>
  );
}
