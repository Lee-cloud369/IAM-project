import React, { useState, useEffect } from 'react';
import { getPrivilegeEscalation } from '../services/api';
import EventDetailModal from '../components/EventDetailModal';

export default function OverviewPage({ searchTerm, onNavigateToAssistant }) {
  const [data, setData] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filterRisk, setFilterRisk] = useState('ALL');
  const [selectedEvent, setSelectedEvent] = useState(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const json = await getPrivilegeEscalation();
      setData(json.data || []);
      setSummary(json.summary || null);
    } catch (err) {
      console.error('Failed to fetch privilege escalation data:', err);
      setError('Could not connect to FastAPI backend at http://127.0.0.1:8000/api/privilege-escalation');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Filter events based on search term & risk selector
  const filteredEvents = data.filter((event) => {
    const matchesSearch =
      !searchTerm ||
      (event.username && event.username.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (event.event && event.event.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (event.policy && event.policy.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (event.source_ip && event.source_ip.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesRisk = filterRisk === 'ALL' || String(event.risk_level).toUpperCase() === filterRisk;
    return matchesSearch && matchesRisk;
  });

  const exportCSV = () => {
    if (!filteredEvents.length) return;
    const headers = ['username', 'event', 'policy', 'risk_level', 'time', 'source_ip'];
    const csvContent =
      'data:text/csv;charset=utf-8,' +
      [headers.join(','), ...filteredEvents.map((e) => headers.map((h) => `"${e[h] || ''}"`).join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', 'privilege_escalation_report.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleInvestigateFromModal = (event) => {
    if (onNavigateToAssistant) {
      onNavigateToAssistant(
        `Investigate privilege escalation event for user '${event.username || 'unknown'}' with action '${event.event || 'unknown'}' and policy '${event.policy || 'N/A'}'. What is the blast radius and how do I remediate?`
      );
    }
  };

  const criticalCount = summary
    ? summary.critical_risk_count
    : data.filter((d) => String(d.risk_level).toUpperCase() === 'CRITICAL').length;
  const highCount = summary
    ? summary.high_risk_count
    : data.filter((d) => String(d.risk_level).toUpperCase() === 'HIGH').length;
  const mediumCount = summary
    ? summary.medium_risk_count
    : data.filter((d) => String(d.risk_level).toUpperCase() === 'MEDIUM').length;
  const totalCount = summary ? summary.total_events : data.length;

  return (
    <div className="space-y-8 animate-fadeIn pt-2 sm:pt-4">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display-hero text-3xl sm:text-display-hero text-primary uppercase tracking-tight drop-shadow-[0_0_15px_rgba(255,255,255,0.2)]">
            Overview & <span className="text-primary-fixed">Privilege Escalation</span>
          </h1>
          <p className="font-body-md text-body-md text-on-surface-variant mt-1">
            Real-time CloudTrail IAM telemetry and risk assessment for privileged identities.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex bg-surface-container-high/60 border border-outline-variant/50 rounded p-0.5">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((risk) => (
              <button
                key={risk}
                onClick={() => setFilterRisk(risk)}
                className={`px-3 py-1.5 rounded font-label-caps text-xs uppercase tracking-wider transition-colors ${
                  filterRisk === risk
                    ? 'bg-primary-fixed text-on-primary-fixed font-bold shadow-[0_0_8px_rgba(190,245,0,0.5)]'
                    : 'text-on-surface-variant hover:text-primary'
                }`}
              >
                {risk}
              </button>
            ))}
          </div>

          <button
            onClick={exportCSV}
            className="px-4 py-2 bg-primary-container text-on-primary-container font-label-caps text-xs uppercase tracking-widest hover:bg-primary-fixed transition-all duration-200 flex items-center gap-2 rounded shadow-[0_0_10px_rgba(190,245,0,0.3)] active:scale-95 font-bold"
          >
            <span className="material-symbols-outlined text-sm">download</span>
            Export CSV
          </button>
        </div>
      </div>

      {/* Error Alert Banner */}
      {error && (
        <div className="p-4 rounded-lg bg-error-container/20 border border-secondary-container text-error flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="material-symbols-outlined">error</span>
            <span className="font-body-md text-sm">{error}</span>
          </div>
          <button
            onClick={fetchData}
            className="px-3 py-1 bg-secondary-container text-white font-label-caps text-xs uppercase rounded font-bold"
          >
            Retry
          </button>
        </div>
      )}

      {/* Bento Metric Cards (4-Column Grid) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Card 1: Total Events */}
        <div className="glass-panel p-6 rounded-lg relative overflow-hidden group hover:border-primary-fixed/50 transition-all duration-300">
          <div className="absolute inset-0 bg-gradient-to-br from-primary-fixed/5 to-transparent pointer-events-none"></div>
          <div className="flex justify-between items-start mb-2">
            <span className="font-label-caps text-label-caps text-on-surface-variant uppercase tracking-widest">
              Total Events
            </span>
            <span className="material-symbols-outlined text-primary-fixed text-opacity-90">
              monitoring
            </span>
          </div>
          <div className="font-metric-lg text-metric-lg text-primary glow-text-lime transition-all duration-300">
            {totalCount.toLocaleString()}
          </div>
          <div className="mt-2 flex items-center gap-1 text-primary-fixed font-label-caps text-xs tracking-wider">
            <span className="material-symbols-outlined text-sm">arrow_upward</span>
            +12% telemetry volume
          </div>
        </div>

        {/* Card 2: Critical Risks (Neon Pink Glow) */}
        <div className="glass-panel p-6 rounded-lg relative overflow-hidden glow-pink group">
          <div className="absolute inset-0 bg-gradient-to-br from-[#FF2E9F]/10 to-transparent pointer-events-none"></div>
          <div className="flex justify-between items-start mb-2">
            <span className="font-label-caps text-label-caps text-secondary uppercase tracking-widest">
              Critical Risk
            </span>
            <span className="material-symbols-outlined text-[#FF2E9F]">
              warning
            </span>
          </div>
          <div className="font-metric-lg text-metric-lg text-primary drop-shadow-[0_0_12px_rgba(255,46,159,0.8)]">
            {criticalCount}
          </div>
          <div className="mt-2 flex items-center gap-1 text-[#FF2E9F] font-label-caps text-xs tracking-wider font-semibold">
            <span className="material-symbols-outlined text-sm animate-bounce">priority_high</span>
            Immediate Action Required
          </div>
        </div>

        {/* Card 3: High Risk (Neon Pink) */}
        <div className="glass-panel p-6 rounded-lg relative overflow-hidden glow-pink group">
          <div className="absolute inset-0 bg-gradient-to-br from-[#FF2E9F]/5 to-transparent pointer-events-none"></div>
          <div className="flex justify-between items-start mb-2">
            <span className="font-label-caps text-label-caps text-secondary uppercase tracking-widest">
              High Risk
            </span>
            <span className="material-symbols-outlined text-[#FF2E9F] opacity-90">
              gpp_bad
            </span>
          </div>
          <div className="font-metric-lg text-metric-lg text-primary drop-shadow-[0_0_10px_rgba(255,46,159,0.5)]">
            {highCount}
          </div>
          <div className="mt-2 flex items-center gap-1 text-on-surface-variant font-label-caps text-xs tracking-wider">
            <span className="material-symbols-outlined text-sm">security_update_warning</span>
            Elevated privileges detected
          </div>
        </div>

        {/* Card 4: Medium Risk (Neon Lime Glow) */}
        <div className="glass-panel p-6 rounded-lg relative overflow-hidden glow-lime group">
          <div className="absolute inset-0 bg-gradient-to-br from-primary-fixed/5 to-transparent pointer-events-none"></div>
          <div className="flex justify-between items-start mb-2">
            <span className="font-label-caps text-label-caps text-on-surface-variant uppercase tracking-widest">
              Medium Risk
            </span>
            <span className="material-symbols-outlined text-primary-fixed">
              gpp_maybe
            </span>
          </div>
          <div className="font-metric-lg text-metric-lg text-primary drop-shadow-[0_0_10px_rgba(198,255,0,0.5)]">
            {mediumCount}
          </div>
          <div className="mt-2 flex items-center gap-1 text-on-surface-variant font-label-caps text-xs tracking-wider">
            <span className="material-symbols-outlined text-sm">horizontal_rule</span>
            Stable posture
          </div>
        </div>
      </div>

      {/* Recent Risk Findings Table */}
      <div className="glass-panel rounded-lg overflow-hidden border border-outline-variant/30 flex flex-col shadow-2xl">
        <div className="p-5 border-b border-outline-variant/30 flex justify-between items-center bg-surface-container-low/50">
          <h2 className="font-headline-sm text-headline-sm text-primary uppercase tracking-wide flex items-center gap-2">
            <span className="material-symbols-outlined text-primary-fixed text-xl">table_chart</span>
            Recent Risk Findings ({filteredEvents.length} records)
          </h2>
          <span className="font-label-caps text-xs text-on-surface-variant tracking-wider uppercase hidden sm:block">
            Source: AWS CloudTrail • Click Row to Inspect
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse cyber-table font-body-md text-sm">
            <thead>
              <tr className="border-b-2 border-primary-fixed bg-surface-container-low/30">
                <th className="px-6 py-4 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest">
                  Timestamp
                </th>
                <th className="px-6 py-4 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest">
                  Identity / User
                </th>
                <th className="px-6 py-4 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest">
                  Event / Action
                </th>
                <th className="px-6 py-4 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest">
                  Attached Policy
                </th>
                <th className="px-6 py-4 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest">
                  Risk Level
                </th>
                <th className="px-6 py-4 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest text-right">
                  Status
                </th>
              </tr>
            </thead>
            <tbody className="text-on-surface divide-y divide-outline-variant/10 font-body-md">
              {loading ? (
                <tr>
                  <td colSpan="6" className="px-6 py-12 text-center text-primary-fixed font-mono text-sm">
                    <span className="material-symbols-outlined animate-spin text-2xl mb-2 block">sync</span>
                    Loading CloudTrail privilege escalation logs...
                  </td>
                </tr>
              ) : filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan="6" className="px-6 py-12 text-center text-on-surface-variant font-mono text-sm">
                    No risk events found matching the filter criteria.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((row, idx) => {
                  const riskUpper = String(row.risk_level || 'LOW').toUpperCase();
                  const isCritical = riskUpper === 'CRITICAL';
                  const isHigh = riskUpper === 'HIGH';

                  return (
                    <tr
                      key={idx}
                      onClick={() => setSelectedEvent(row)}
                      className="hover:bg-primary-fixed/5 cursor-pointer transition-colors group"
                    >
                      {/* Timestamp */}
                      <td className="px-6 py-4 whitespace-nowrap text-on-surface-variant font-mono text-xs">
                        {row.time || 'Live Telemetry'}
                      </td>

                      {/* Username */}
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <span className="material-symbols-outlined text-sm text-primary-fixed opacity-70">
                            person
                          </span>
                          <span className="font-semibold text-primary font-mono text-xs group-hover:text-primary-fixed transition-colors">
                            {row.username || 'unknown'}
                          </span>
                        </div>
                      </td>

                      {/* Event */}
                      <td className="px-6 py-4 font-mono text-xs text-on-surface">
                        {row.event || 'N/A'}
                      </td>

                      {/* Policy */}
                      <td className="px-6 py-4 font-mono text-xs text-on-surface-variant max-w-xs truncate">
                        {row.policy || 'N/A'}
                      </td>

                      {/* Risk Badge */}
                      <td className="px-6 py-4">
                        {isCritical ? (
                          <span className="inline-flex items-center px-2.5 py-1 bg-[#FF2E9F] text-black font-label-caps text-xs uppercase tracking-wider rounded font-bold drop-shadow-[0_0_8px_rgba(255,46,159,0.7)]">
                            Critical
                          </span>
                        ) : isHigh ? (
                          <span className="inline-flex items-center px-2.5 py-1 bg-surface-container-highest text-[#FF2E9F] border border-[#FF2E9F] font-label-caps text-xs uppercase tracking-wider rounded font-semibold">
                            High Risk
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-2.5 py-1 bg-surface-container-highest text-primary-fixed border border-primary-fixed font-label-caps text-xs uppercase tracking-wider rounded">
                            {row.risk_level || 'Medium'}
                          </span>
                        )}
                      </td>

                      {/* Status */}
                      <td className="px-6 py-4 text-right">
                        {isCritical || isHigh ? (
                          <span className="text-secondary flex items-center justify-end gap-1.5 font-label-caps text-xs uppercase tracking-wider font-bold">
                            <span className="w-2 h-2 rounded-full bg-[#FF2E9F] animate-pulse"></span>
                            Active
                          </span>
                        ) : (
                          <span className="text-primary-fixed flex items-center justify-end gap-1.5 font-label-caps text-xs uppercase tracking-wider">
                            <span className="w-2 h-2 rounded-full bg-primary-fixed"></span>
                            Monitored
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Deep Inspection Modal */}
      {selectedEvent && (
        <EventDetailModal
          item={selectedEvent}
          type="Privilege Escalation Event"
          onClose={() => setSelectedEvent(null)}
          onInvestigate={handleInvestigateFromModal}
        />
      )}
    </div>
  );
}
