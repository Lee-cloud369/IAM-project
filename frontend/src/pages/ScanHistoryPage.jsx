import React, { useState, useEffect } from 'react';
import { getScanHistory } from '../services/api';

export default function ScanHistoryPage({ searchTerm, onNavigateToAssistant }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filterType, setFilterType] = useState('ALL');
  const [expandedRows, setExpandedRows] = useState(new Set());
  const [selectedScanForModal, setSelectedScanForModal] = useState(null);
  const [copiedId, setCopiedId] = useState(null);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await getScanHistory();
      if (response && response.data) {
        setHistory(response.data);
      } else {
        setHistory([]);
      }
    } catch (err) {
      console.error('Failed to fetch scan history from DynamoDB:', err);
      setError('Could not connect to FastAPI backend or DynamoDB table. Make sure the backend server is running on http://127.0.0.1:8000.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const toggleRow = (findingId) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(findingId)) {
        next.delete(findingId);
      } else {
        next.add(findingId);
      }
      return next;
    });
  };

  const handleCopy = (id, text) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Filter history based on search term & scan type selector
  const filteredHistory = history.filter((item) => {
    const sTerm = searchTerm ? searchTerm.toLowerCase() : '';
    const findingId = item.finding_id ? String(item.finding_id).toLowerCase() : '';
    const scanId = item.scan_id ? String(item.scan_id).toLowerCase() : '';
    const scanType = item.scan_type ? String(item.scan_type).toLowerCase() : '';
    const timestamp = item.timestamp ? String(item.timestamp).toLowerCase() : '';
    const rawData = item.finding_data ? JSON.stringify(item.finding_data).toLowerCase() : '';

    const matchesSearch =
      !sTerm ||
      findingId.includes(sTerm) ||
      scanId.includes(sTerm) ||
      scanType.includes(sTerm) ||
      timestamp.includes(sTerm) ||
      rawData.includes(sTerm);

    const matchesType =
      filterType === 'ALL' ||
      item.scan_type === filterType ||
      (filterType === 'privilege_escalation' && item.scan_type === 'privilege_escalation') ||
      (filterType === 'drift' && item.scan_type === 'drift') ||
      (filterType === 'credential_hygiene' && item.scan_type === 'credential_hygiene');

    return matchesSearch && matchesType;
  });

  // Calculate Breakdown Statistics
  const totalScans = history.length;
  const privEscScans = history.filter((h) => h.scan_type === 'privilege_escalation').length;
  const driftScans = history.filter((h) => h.scan_type === 'drift').length;
  const hygieneScans = history.filter((h) => h.scan_type === 'credential_hygiene').length;

  const getScanBadge = (scanType) => {
    switch (scanType) {
      case 'privilege_escalation':
        return (
          <span className="px-2.5 py-1 rounded bg-[#FF2E9F]/15 border border-[#FF2E9F] text-[#FF2E9F] font-label-caps text-xs uppercase tracking-wider font-bold shadow-[0_0_8px_rgba(255,46,159,0.3)] inline-flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#FF2E9F] animate-pulse"></span>
            Privilege Escalation
          </span>
        );
      case 'drift':
        return (
          <span className="px-2.5 py-1 rounded bg-primary-fixed/15 border border-primary-fixed text-primary-fixed font-label-caps text-xs uppercase tracking-wider font-bold shadow-[0_0_8px_rgba(190,245,0,0.3)] inline-flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-primary-fixed"></span>
            Privilege Drift
          </span>
        );
      case 'credential_hygiene':
        return (
          <span className="px-2.5 py-1 rounded bg-cyan-500/15 border border-cyan-400 text-cyan-300 font-label-caps text-xs uppercase tracking-wider font-bold shadow-[0_0_8px_rgba(6,182,212,0.3)] inline-flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
            Credential Hygiene
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-1 rounded bg-surface-container-high border border-outline-variant text-on-surface-variant font-label-caps text-xs uppercase tracking-wider font-bold inline-flex items-center gap-1.5">
            {scanType || 'Unknown'}
          </span>
        );
    }
  };

  const formatTimestamp = (ts) => {
    if (!ts) return 'N/A';
    try {
      const date = new Date(ts);
      return date.toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    } catch {
      return ts;
    }
  };

  const getSummaryInsights = (findingData) => {
    if (!findingData) return null;
    let dataObj = findingData;
    if (typeof findingData === 'string') {
      try {
        dataObj = JSON.parse(findingData);
      } catch {
        return null;
      }
    }

    if (dataObj.summary) {
      const s = dataObj.summary;
      if (s.critical_risk_count !== undefined) {
        return (
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-[#FF2E9F] font-bold">Crit: {s.critical_risk_count}</span>
            <span className="text-secondary">High: {s.high_risk_count}</span>
            <span className="text-primary-fixed">Total: {s.total_events}</span>
          </div>
        );
      }
      if (s.unused_permissions_count !== undefined) {
        return (
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-[#FF2E9F] font-bold">Unused: {s.unused_permissions_count}</span>
            <span className="text-primary-fixed">Analyzed: {s.total_permissions_analyzed}</span>
          </div>
        );
      }
      if (s.users_without_mfa !== undefined) {
        return (
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-[#FF2E9F] font-bold">No MFA: {s.users_without_mfa}</span>
            <span className="text-secondary">Stale Keys: {s.keys_needing_rotation}</span>
          </div>
        );
      }
    }
    return null;
  };

  const exportJSON = () => {
    if (!filteredHistory.length) return;
    const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(
      JSON.stringify(filteredHistory, null, 2)
    )}`;
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', jsonString);
    downloadAnchor.setAttribute('download', `aether_aran_scan_history_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-8 animate-fadeIn pt-2 sm:pt-4">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display-hero text-3xl sm:text-display-hero text-primary uppercase tracking-tight drop-shadow-[0_0_15px_rgba(255,255,255,0.2)]">
            DynamoDB <span className="text-primary-fixed">Scan History</span>
          </h1>
          <p className="font-body-md text-body-md text-on-surface-variant mt-1">
            Immutable audit log of IAM telemetry findings stored in AWS DynamoDB (<span className="text-primary-fixed font-mono">AetherAranFindings</span>).
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Scan Type Filter Pills */}
          <div className="flex bg-surface-container-high/60 border border-outline-variant/50 rounded p-0.5">
            {[
              { id: 'ALL', label: 'ALL' },
              { id: 'privilege_escalation', label: 'Escalation' },
              { id: 'drift', label: 'Drift' },
              { id: 'credential_hygiene', label: 'Hygiene' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setFilterType(tab.id)}
                className={`px-3 py-1.5 rounded font-label-caps text-xs uppercase tracking-wider transition-all ${
                  filterType === tab.id
                    ? 'bg-primary-fixed text-on-primary-fixed font-bold shadow-[0_0_8px_rgba(190,245,0,0.5)]'
                    : 'text-on-surface-variant hover:text-primary'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Refresh Button */}
          <button
            onClick={fetchHistory}
            disabled={loading}
            className="px-3.5 py-2 bg-surface-container-high border border-outline-variant/50 text-on-surface hover:text-primary-fixed hover:border-primary-fixed/50 font-label-caps text-xs uppercase tracking-widest transition-all rounded flex items-center gap-1.5 disabled:opacity-50 font-bold"
            title="Reload from DynamoDB"
          >
            <span className={`material-symbols-outlined text-sm ${loading ? 'animate-spin text-primary-fixed' : ''}`}>
              refresh
            </span>
            <span className="hidden sm:inline">Refresh</span>
          </button>

          {/* Export JSON Button */}
          <button
            onClick={exportJSON}
            disabled={!filteredHistory.length}
            className="px-4 py-2 bg-primary-container text-on-primary-container font-label-caps text-xs uppercase tracking-widest hover:bg-primary-fixed transition-all duration-200 flex items-center gap-2 rounded shadow-[0_0_10px_rgba(190,245,0,0.3)] active:scale-95 disabled:opacity-40 font-bold"
          >
            <span className="material-symbols-outlined text-sm">download</span>
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Error Alert Banner */}
      {error && (
        <div className="p-4 rounded-lg bg-error-container/20 border border-secondary-container text-error flex items-center justify-between shadow-lg animate-fadeIn">
          <div className="flex items-center gap-3">
            <span className="material-symbols-outlined text-xl">error</span>
            <span className="font-body-md text-sm">{error}</span>
          </div>
          <button
            onClick={fetchHistory}
            className="px-3 py-1 bg-secondary-container text-white font-label-caps text-xs uppercase rounded font-bold hover:bg-[#FF2E9F] transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {/* 4-Card Bento Metric Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Card 1: Total Scans Logged */}
        <div className="glass-panel p-6 rounded-lg relative overflow-hidden group hover:border-primary-fixed/50 transition-all duration-300">
          <div className="absolute inset-0 bg-gradient-to-br from-primary-fixed/5 to-transparent pointer-events-none"></div>
          <div className="flex justify-between items-start mb-2">
            <span className="font-label-caps text-label-caps text-on-surface-variant uppercase tracking-widest">
              Total Scans Logged
            </span>
            <span className="material-symbols-outlined text-primary-fixed text-opacity-90">
              database
            </span>
          </div>
          <div className="font-metric-lg text-metric-lg text-primary glow-text-lime transition-all duration-300">
            {totalScans.toLocaleString()}
          </div>
          <div className="mt-2 flex items-center gap-1 text-primary-fixed font-label-caps text-xs tracking-wider">
            <span className="material-symbols-outlined text-sm">check_circle</span>
            AWS DynamoDB Active
          </div>
        </div>

        {/* Card 2: Privilege Escalation Scans (Magenta Glow) */}
        <div className="glass-panel p-6 rounded-lg relative overflow-hidden glow-pink group">
          <div className="absolute inset-0 bg-gradient-to-br from-[#FF2E9F]/10 to-transparent pointer-events-none"></div>
          <div className="flex justify-between items-start mb-2">
            <span className="font-label-caps text-label-caps text-[#ffb0cd] uppercase tracking-widest">
              Privilege Escalation
            </span>
            <span className="material-symbols-outlined text-[#FF2E9F]">
              security
            </span>
          </div>
          <div className="font-metric-lg text-metric-lg text-white glow-text-pink">
            {privEscScans.toLocaleString()}
          </div>
          <div className="mt-2 flex items-center gap-1 text-[#FF2E9F] font-label-caps text-xs tracking-wider">
            <span className="material-symbols-outlined text-sm">radar</span>
            CloudTrail Telemetry Runs
          </div>
        </div>

        {/* Card 3: Least-Privilege Drift Scans (Lime Glow) */}
        <div className="glass-panel p-6 rounded-lg relative overflow-hidden glow-lime group">
          <div className="absolute inset-0 bg-gradient-to-br from-primary-fixed/10 to-transparent pointer-events-none"></div>
          <div className="flex justify-between items-start mb-2">
            <span className="font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest">
              Privilege Drift
            </span>
            <span className="material-symbols-outlined text-primary-fixed">
              trending_down
            </span>
          </div>
          <div className="font-metric-lg text-metric-lg text-white glow-text-lime">
            {driftScans.toLocaleString()}
          </div>
          <div className="mt-2 flex items-center gap-1 text-primary-fixed font-label-caps text-xs tracking-wider">
            <span className="material-symbols-outlined text-sm">insights</span>
            Access Advisor Audits
          </div>
        </div>

        {/* Card 4: Credential Hygiene Scans (Cyan Glow) */}
        <div className="glass-panel p-6 rounded-lg relative overflow-hidden group hover:border-cyan-400/50 transition-all duration-300 border border-cyan-500/20">
          <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/10 to-transparent pointer-events-none"></div>
          <div className="flex justify-between items-start mb-2">
            <span className="font-label-caps text-label-caps text-cyan-200 uppercase tracking-widest">
              Credential Hygiene
            </span>
            <span className="material-symbols-outlined text-cyan-400">
              password
            </span>
          </div>
          <div className="font-metric-lg text-metric-lg text-cyan-100 drop-shadow-[0_0_12px_rgba(6,182,212,0.8)]">
            {hygieneScans.toLocaleString()}
          </div>
          <div className="mt-2 flex items-center gap-1 text-cyan-300 font-label-caps text-xs tracking-wider">
            <span className="material-symbols-outlined text-sm">lock_reset</span>
            MFA & Key Posture Runs
          </div>
        </div>
      </div>

      {/* Main Table Panel */}
      <div className="glass-panel rounded-lg overflow-hidden border border-outline-variant/40 shadow-2xl">
        <div className="p-5 border-b border-outline-variant/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-surface-container-low/50">
          <div className="flex items-center gap-3">
            <span className="material-symbols-outlined text-primary-fixed text-2xl">
              receipt_long
            </span>
            <div>
              <h2 className="font-headline-sm text-lg text-primary uppercase tracking-wide">
                Recorded Telemetry Scans
              </h2>
              <span className="font-label-caps text-[11px] text-on-surface-variant uppercase tracking-wider">
                Showing {filteredHistory.length} of {totalScans} audit logs
              </span>
            </div>
          </div>
          <div className="text-xs font-mono text-on-surface-variant flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-primary-fixed animate-pulse"></span>
            <span>Table: <span className="text-primary-fixed">AetherAranFindings</span></span>
          </div>
        </div>

        {/* Loading Spinner State */}
        {loading && history.length === 0 ? (
          <div className="py-20 flex flex-col items-center justify-center gap-4 text-center">
            <span className="material-symbols-outlined text-4xl text-primary-fixed animate-spin">
              sync
            </span>
            <div className="font-label-caps text-sm text-primary-fixed uppercase tracking-widest">
              Connecting to DynamoDB & loading scan records...
            </div>
          </div>
        ) : filteredHistory.length === 0 ? (
          /* Empty State */
          <div className="py-20 px-6 text-center flex flex-col items-center justify-center">
            <div className="w-16 h-16 rounded-2xl bg-surface-container-high border border-outline-variant/50 flex items-center justify-center mb-4 text-on-surface-variant shadow-inner">
              <span className="material-symbols-outlined text-3xl text-primary-fixed/70">
                manage_history
              </span>
            </div>
            <h3 className="font-headline-sm text-lg text-primary uppercase tracking-wider">
              No Scan History Records Found
            </h3>
            <p className="font-body-md text-sm text-on-surface-variant max-w-md mt-1 mb-6">
              {searchTerm || filterType !== 'ALL'
                ? 'No scan records match your active search or filter criteria. Try resetting the filter.'
                : 'Scans will appear here automatically when you run Privilege Escalation, Drift, or Credential Hygiene audits.'}
            </p>
            <button
              onClick={fetchHistory}
              className="px-4 py-2 bg-primary-fixed text-on-primary-fixed font-label-caps text-xs uppercase tracking-widest rounded hover:bg-primary-fixed-dim transition-all font-bold flex items-center gap-2 shadow-[0_0_12px_rgba(190,245,0,0.4)]"
            >
              <span className="material-symbols-outlined text-base">refresh</span>
              Check Again
            </button>
          </div>
        ) : (
          /* Records Table */
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse cyber-table">
              <thead>
                <tr className="border-b-2 border-primary-fixed bg-surface-container-highest/60 text-on-surface-variant font-label-caps text-[11px] uppercase tracking-widest select-none">
                  <th className="py-3.5 px-4">Scan Type</th>
                  <th className="py-3.5 px-4">Timestamp (UTC)</th>
                  <th className="py-3.5 px-4">Finding ID</th>
                  <th className="py-3.5 px-4">Telemetry Summary</th>
                  <th className="py-3.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-outline-variant/20 text-xs font-body-md">
                {filteredHistory.map((item) => {
                  const isExpanded = expandedRows.has(item.finding_id);
                  const insights = getSummaryInsights(item.finding_data);

                  return (
                    <React.Fragment key={item.finding_id}>
                      <tr
                        className={`transition-colors cursor-pointer ${
                          isExpanded ? 'bg-primary-fixed/5' : 'hover:bg-primary-fixed/5'
                        }`}
                        onClick={() => toggleRow(item.finding_id)}
                      >
                        {/* Scan Type */}
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          {getScanBadge(item.scan_type)}
                        </td>

                        {/* Timestamp */}
                        <td className="py-3.5 px-4 whitespace-nowrap font-mono text-on-surface">
                          <div className="flex items-center gap-1.5">
                            <span className="material-symbols-outlined text-xs text-on-surface-variant">
                              schedule
                            </span>
                            <span>{formatTimestamp(item.timestamp)}</span>
                          </div>
                        </td>

                        {/* Finding ID */}
                        <td className="py-3.5 px-4 whitespace-nowrap font-mono">
                          <div className="flex items-center gap-2">
                            <span className="text-primary-fixed text-[11px] font-semibold" title={item.finding_id}>
                              {item.finding_id ? `${String(item.finding_id).slice(0, 13)}...` : 'N/A'}
                            </span>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleCopy(item.finding_id, item.finding_id);
                              }}
                              className="text-on-surface-variant hover:text-primary-fixed p-1 transition-colors"
                              title="Copy Finding ID"
                            >
                              <span className="material-symbols-outlined text-xs">
                                {copiedId === item.finding_id ? 'check' : 'content_copy'}
                              </span>
                            </button>
                          </div>
                        </td>

                        {/* Telemetry Summary */}
                        <td className="py-3.5 px-4">
                          {insights || (
                            <span className="text-on-surface-variant text-[11px] font-mono italic">
                              Payload saved ({typeof item.finding_data === 'object' ? 'Structured' : 'Raw'})
                            </span>
                          )}
                        </td>

                        {/* Actions Button */}
                        <td className="py-3.5 px-4 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={() => toggleRow(item.finding_id)}
                              className="px-2.5 py-1 rounded bg-surface-container-high hover:bg-primary-fixed hover:text-on-primary-fixed border border-outline-variant/40 text-on-surface font-label-caps text-xs uppercase tracking-wider transition-all flex items-center gap-1"
                            >
                              <span>{isExpanded ? 'Collapse' : 'Details'}</span>
                              <span className="material-symbols-outlined text-sm">
                                {isExpanded ? 'expand_less' : 'expand_more'}
                              </span>
                            </button>

                            <button
                              onClick={() => setSelectedScanForModal(item)}
                              className="p-1 rounded bg-surface-container-high hover:bg-primary-fixed hover:text-on-primary-fixed border border-outline-variant/40 text-on-surface transition-all"
                              title="Full Screen Inspection"
                            >
                              <span className="material-symbols-outlined text-base">open_in_new</span>
                            </button>
                          </div>
                        </td>
                      </tr>

                      {/* Expandable Row Detail Drawer */}
                      {isExpanded && (
                        <tr className="bg-surface-container-lowest/80 border-b border-primary-fixed/30">
                          <td colSpan={5} className="p-5">
                            <div className="space-y-4 animate-fadeIn">
                              {/* Header Meta Bar */}
                              <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-outline-variant/30">
                                <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
                                  <div>
                                    <span className="text-on-surface-variant">Finding ID: </span>
                                    <span className="text-primary-fixed font-bold">{item.finding_id}</span>
                                  </div>
                                  <div>
                                    <span className="text-on-surface-variant">Scan ID: </span>
                                    <span className="text-on-surface">{item.scan_id || 'N/A'}</span>
                                  </div>
                                  <div>
                                    <span className="text-on-surface-variant">Recorded: </span>
                                    <span className="text-on-surface">{item.timestamp}</span>
                                  </div>
                                </div>

                                <div className="flex items-center gap-2">
                                  <button
                                    onClick={() => handleCopy(item.finding_id + '_json', typeof item.finding_data === 'string' ? item.finding_data : JSON.stringify(item.finding_data, null, 2))}
                                    className="px-2.5 py-1 bg-surface-container-high hover:bg-surface-variant border border-outline-variant/40 rounded text-xs font-label-caps uppercase text-primary-fixed flex items-center gap-1 transition-colors"
                                  >
                                    <span className="material-symbols-outlined text-xs">
                                      {copiedId === item.finding_id + '_json' ? 'check' : 'content_copy'}
                                    </span>
                                    <span>{copiedId === item.finding_id + '_json' ? 'Copied' : 'Copy JSON'}</span>
                                  </button>

                                  {onNavigateToAssistant && (
                                    <button
                                      onClick={() =>
                                        onNavigateToAssistant(
                                          `Analyze this historical ${item.scan_type} scan from DynamoDB (Finding ID: ${item.finding_id}). Summary: ${JSON.stringify(
                                            item.finding_data?.summary || {}
                                          )}. What are the key risk takeaways?`
                                        )
                                      }
                                      className="px-2.5 py-1 bg-primary-fixed text-on-primary-fixed rounded text-xs font-label-caps uppercase font-bold flex items-center gap-1 shadow-[0_0_8px_rgba(190,245,0,0.4)]"
                                    >
                                      <span className="material-symbols-outlined text-xs">smart_toy</span>
                                      <span>Ask NIMORA</span>
                                    </button>
                                  )}
                                </div>
                              </div>

                              {/* Formatted JSON Payload Preview */}
                              <div>
                                <span className="font-label-caps text-xs text-on-surface-variant uppercase tracking-wider block mb-1.5 flex items-center gap-1.5">
                                  <span className="material-symbols-outlined text-sm text-primary-fixed">code</span>
                                  Full finding_data JSON Payload:
                                </span>
                                <pre className="bg-surface-container-lowest p-4 rounded-lg border border-outline-variant/40 text-primary-fixed font-mono text-xs overflow-x-auto max-h-72 select-text shadow-inner">
                                  {typeof item.finding_data === 'string'
                                    ? item.finding_data
                                    : JSON.stringify(item.finding_data, null, 2)}
                                </pre>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Full Modal Inspection for Selected Scan */}
      {selectedScanForModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
          <div className="glass-panel w-full max-w-3xl rounded-xl border border-primary-fixed/50 shadow-[0_0_35px_rgba(190,245,0,0.25)] overflow-hidden flex flex-col max-h-[90vh]">
            {/* Modal Header */}
            <div className="p-5 border-b border-outline-variant/30 flex items-center justify-between bg-surface-container-low/90">
              <div className="flex items-center gap-3">
                <span className="material-symbols-outlined text-primary-fixed text-2xl">
                  database
                </span>
                <div>
                  <h3 className="font-headline-sm text-lg text-primary uppercase tracking-wide">
                    DynamoDB Scan Finding Record
                  </h3>
                  <p className="font-label-caps text-[11px] text-on-surface-variant uppercase tracking-wider">
                    Type: {selectedScanForModal.scan_type} • ID: {selectedScanForModal.finding_id}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedScanForModal(null)}
                className="p-1.5 text-on-surface-variant hover:text-primary hover:bg-surface-variant/50 rounded transition-colors"
              >
                <span className="material-symbols-outlined text-xl">close</span>
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-5 overflow-y-auto font-body-md text-sm">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-3 rounded bg-surface-container-high/60 border border-outline-variant/30">
                  <span className="font-label-caps text-[10px] text-on-surface-variant uppercase tracking-wider block">
                    Scan Type
                  </span>
                  <div className="mt-1">{getScanBadge(selectedScanForModal.scan_type)}</div>
                </div>

                <div className="p-3 rounded bg-surface-container-high/60 border border-outline-variant/30">
                  <span className="font-label-caps text-[10px] text-on-surface-variant uppercase tracking-wider block">
                    Timestamp
                  </span>
                  <span className="font-mono text-xs text-primary block mt-1">
                    {formatTimestamp(selectedScanForModal.timestamp)}
                  </span>
                </div>

                <div className="p-3 rounded bg-surface-container-high/60 border border-outline-variant/30">
                  <span className="font-label-caps text-[10px] text-on-surface-variant uppercase tracking-wider block">
                    Finding ID (Partition Key)
                  </span>
                  <span className="font-mono text-xs text-primary-fixed font-semibold block mt-1 break-all">
                    {selectedScanForModal.finding_id}
                  </span>
                </div>

                <div className="p-3 rounded bg-surface-container-high/60 border border-outline-variant/30">
                  <span className="font-label-caps text-[10px] text-on-surface-variant uppercase tracking-wider block">
                    Scan ID (Sort Key)
                  </span>
                  <span className="font-mono text-xs text-on-surface block mt-1 break-all">
                    {selectedScanForModal.scan_id || 'N/A'}
                  </span>
                </div>
              </div>

              {/* Complete JSON Viewer */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-label-caps text-xs text-on-surface-variant uppercase tracking-wider flex items-center gap-1.5">
                    <span className="material-symbols-outlined text-sm text-primary-fixed">code</span>
                    Full JSON finding_data:
                  </span>
                  <button
                    onClick={() =>
                      handleCopy(
                        'modal_json',
                        typeof selectedScanForModal.finding_data === 'string'
                          ? selectedScanForModal.finding_data
                          : JSON.stringify(selectedScanForModal.finding_data, null, 2)
                      )
                    }
                    className="text-xs font-label-caps text-primary-fixed hover:underline uppercase flex items-center gap-1"
                  >
                    <span className="material-symbols-outlined text-xs">
                      {copiedId === 'modal_json' ? 'check' : 'content_copy'}
                    </span>
                    <span>{copiedId === 'modal_json' ? 'Copied' : 'Copy Payload'}</span>
                  </button>
                </div>
                <pre className="bg-surface-container-lowest p-4 rounded-lg border border-outline-variant/40 text-primary-fixed font-mono text-xs overflow-x-auto max-h-64 select-text">
                  {typeof selectedScanForModal.finding_data === 'string'
                    ? selectedScanForModal.finding_data
                    : JSON.stringify(selectedScanForModal.finding_data, null, 2)}
                </pre>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-outline-variant/30 bg-surface-container-low/90 flex items-center justify-between">
              <button
                onClick={() => setSelectedScanForModal(null)}
                className="px-4 py-2 text-xs font-label-caps uppercase tracking-wider border border-outline-variant/40 rounded hover:bg-surface-variant/40 transition-colors text-on-surface"
              >
                Close
              </button>

              {onNavigateToAssistant && (
                <button
                  onClick={() => {
                    const scan = selectedScanForModal;
                    setSelectedScanForModal(null);
                    onNavigateToAssistant(
                      `Analyze this historical ${scan.scan_type} scan from DynamoDB (Finding ID: ${scan.finding_id}). Summary: ${JSON.stringify(
                        scan.finding_data?.summary || {}
                      )}. What are the key risk takeaways?`
                    );
                  }}
                  className="px-4 py-2 bg-primary-fixed text-on-primary-fixed text-xs font-label-caps uppercase tracking-widest rounded hover:bg-primary transition-all font-bold flex items-center gap-2 shadow-[0_0_12px_rgba(190,245,0,0.4)]"
                >
                  <span className="material-symbols-outlined text-base">smart_toy</span>
                  Investigate with NIMORA
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
