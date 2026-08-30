import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';

export default function TopNavBar({
  searchTerm,
  setSearchTerm,
  onRefresh,
  isRefreshing,
  lastRefreshedText,
  onOpenMobileMenu,
}) {
  const { user, logout } = useAuth();
  const [showNotifications, setShowNotifications] = useState(false);

  const notifications = [
    {
      id: 1,
      title: 'AttachUserPolicy Escalation',
      desc: 'Critical risk detected on alice-admin',
      time: '2m ago',
      level: 'critical',
    },
    {
      id: 2,
      title: 'Unused Administrator Access',
      desc: '142 identities with 35% drift gap',
      time: '14m ago',
      level: 'warning',
    },
    {
      id: 3,
      title: 'MFA Non-Compliance',
      desc: '3 user accounts missing 2FA',
      time: '1h ago',
      level: 'critical',
    },
  ];

  // User display name from AWS Cognito claims
  const userEmail = user?.email || 'analyst@aetheraran.io';
  const userName = user?.username || userEmail.split('@')[0];

  return (
    <header className="w-full h-16 top-0 sticky bg-surface/80 backdrop-blur-xl flex items-center justify-between px-4 sm:px-6 border-b border-outline-variant/30 shadow-[0_0_20px_rgba(166,215,0,0.08)] z-30 transition-all duration-300">
      {/* Brand Title / Mobile Menu Button */}
      <div className="flex items-center gap-3">
        <button
          onClick={onOpenMobileMenu}
          className="md:hidden p-2 text-on-surface hover:text-primary-fixed hover:bg-surface-container-high rounded transition-colors"
          title="Open Menu"
        >
          <span className="material-symbols-outlined text-2xl">menu</span>
        </button>

        <div className="hidden md:block">
          <span className="font-display-hero text-headline-sm uppercase tracking-tighter text-primary">
            AETHER ARAN
          </span>
        </div>
        <span className="md:hidden font-display-hero text-base uppercase tracking-tighter text-primary-fixed font-bold">
          AETHER ARAN
        </span>
      </div>

      {/* Search Input Box */}
      <div className="flex-1 max-w-md mx-2 sm:mx-6 md:mx-8 relative">
        <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-base pointer-events-none">
          search
        </span>
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Search identities, actions, policies, ARNs..."
          className="w-full bg-surface-container-high/60 border border-outline-variant/40 rounded py-1.5 pl-9 pr-8 text-sm font-body-md text-on-surface focus:outline-none focus:border-primary-fixed focus:shadow-[0_0_10px_rgba(190,245,0,0.25)] transition-all placeholder:text-on-surface-variant/50"
        />
        {searchTerm && (
          <button
            onClick={() => setSearchTerm('')}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-primary p-0.5"
          >
            <span className="material-symbols-outlined text-sm">close</span>
          </button>
        )}
      </div>

      {/* Right Telemetry Controls & User Status */}
      <div className="flex items-center gap-2 sm:gap-4 relative">
        <span className="font-label-caps text-label-caps text-on-surface-variant hidden xl:block tracking-wider uppercase text-xs">
          {lastRefreshedText || 'Refreshed: live'}
        </span>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          title="Refresh Telemetry Data"
          className="p-2 text-on-surface-variant hover:text-primary-fixed hover:bg-surface-variant/30 rounded transition-all flex items-center justify-center"
        >
          <span className={`material-symbols-outlined text-lg ${isRefreshing ? 'animate-spin text-primary-fixed' : ''}`}>
            refresh
          </span>
        </button>

        {/* Notifications Popover Trigger */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            title="Security Notifications"
            className="p-2 text-on-surface-variant hover:text-primary hover:bg-surface-variant/30 rounded transition-all relative"
          >
            <span className="material-symbols-outlined text-lg">notifications</span>
            <span className="w-2 h-2 rounded-full bg-[#FF2E9F] absolute top-1.5 right-1.5 shadow-[0_0_8px_#FF2E9F] animate-pulse"></span>
          </button>

          {/* Notifications Dropdown */}
          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 glass-panel rounded-lg border border-outline-variant/50 shadow-2xl p-4 space-y-3 z-50 animate-fadeIn">
              <div className="flex justify-between items-center pb-2 border-b border-outline-variant/30">
                <span className="font-label-caps text-xs text-primary-fixed uppercase tracking-wider font-bold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-[#FF2E9F] animate-pulse"></span>
                  Active Alerts ({notifications.length})
                </span>
                <button
                  onClick={() => setShowNotifications(false)}
                  className="text-on-surface-variant hover:text-primary text-xs"
                >
                  <span className="material-symbols-outlined text-sm">close</span>
                </button>
              </div>

              <div className="space-y-2 max-h-60 overflow-y-auto">
                {notifications.map((n) => (
                  <div
                    key={n.id}
                    className="p-2.5 rounded bg-surface-container-high/60 border border-outline-variant/20 text-xs font-body-md"
                  >
                    <div className="flex justify-between items-center">
                      <span className="font-semibold text-primary">{n.title}</span>
                      <span className="text-[10px] text-on-surface-variant font-mono">{n.time}</span>
                    </div>
                    <p className="text-on-surface-variant mt-1 text-[11px] leading-tight">{n.desc}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Real Authenticated Cognito User Profile */}
        <div className="flex items-center gap-2 pl-2 sm:pl-3 border-l border-outline-variant/30">
          <div className="w-8 h-8 rounded-full border border-primary-fixed overflow-hidden bg-surface-variant flex items-center justify-center shadow-[0_0_8px_rgba(190,245,0,0.3)]">
            <span className="material-symbols-outlined text-primary-fixed text-base">
              person
            </span>
          </div>
          <div className="hidden lg:block max-w-[160px] truncate">
            <div className="font-label-caps text-xs text-primary leading-none truncate font-bold" title={userEmail}>
              {userEmail}
            </div>
            <div className="text-[10px] text-primary-fixed leading-none mt-0.5 font-mono">
              Cognito Verified
            </div>
          </div>

          {/* Working Logout Button */}
          <button
            onClick={logout}
            title="Log Out of AWS Cognito"
            className="ml-1 sm:ml-2 p-1.5 sm:px-2.5 sm:py-1 rounded-lg border border-outline-variant/40 hover:border-[#FF2E9F]/60 text-on-surface-variant hover:text-[#FF2E9F] hover:bg-[#FF2E9F]/10 font-label-caps text-xs uppercase tracking-wider flex items-center gap-1 transition-all"
          >
            <span className="material-symbols-outlined text-base sm:text-sm">logout</span>
            <span className="hidden sm:inline">Logout</span>
          </button>
        </div>
      </div>
    </header>
  );
}
