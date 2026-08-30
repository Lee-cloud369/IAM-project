import React, { useState, useEffect } from 'react';
import { getDriftReport, remediateDrift, remediateAllDrift } from '../services/api';
import EventDetailModal from '../components/EventDetailModal';

export default function DriftAnalyzerPage({ searchTerm, onNavigateToAssistant }) {
  const [rows, setRows] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [remediated, setRemediated] = useState({});
  const [remediatingRows, setRemediatingRows] = useState({});
  const [remediatingAll, setRemediatingAll] = useState(false);
  const [toastMessage, setToastMessage] = useState('');
  const [toastType, setToastType] = useState('success');
  const [selectedItem, setSelectedItem] = useState(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const json = await getDriftReport();
      setRows(json.data || []);
      setSummary(json.summary || null);
    } catch (err) {
      console.error('Failed to fetch drift report:', err);
      setError('Could not connect to FastAPI backend at http://127.0.0.1:8000/api/drift-report');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const showToast = (msg, type = 'success') => {
    setToastMessage(msg);
    setToastType(type);
    setTimeout(() => setToastMessage(''), 4500);
  };

  const handleRevoke = async (e, idx, row) => {
    e.stopPropagation();
    if (remediatingRows[idx] || remediated[idx]) return;

    setRemediatingRows((prev) => ({ ...prev, [idx]: true }));
    try {
      const resp = await remediateDrift(row.username, row.policy, row.service);
      setRemediated((prev) => ({ ...prev, [idx]: true }));
      showToast(
        resp?.message || `Access revoked for service '${row.service}' on user '${row.username}'`,
        'success'
      );
    } catch (err) {
      console.error('Failed to revoke access:', err);
      showToast(
        `Failed to revoke access for '${row.service}': ${err.message || 'Server error'}`,
        'error'
      );
    } finally {
      setRemediatingRows((prev) => ({ ...prev, [idx]: false }));
    }
  };

  const handleRemediateAll = async () => {
    if (remediatingAll || rows.length === 0) return;
    setRemediatingAll(true);
    try {
      const resp = await remediateAllDrift(filteredRows);
      const all = {};
      rows.forEach((_, idx) => {
        all[idx] = true;
      });
      setRemediated(all);
      showToast(
        resp?.message || `Successfully remediated drift across all ${rows.length} evaluated permissions!`,
        'success'
      );
    } catch (err) {
      console.error('Failed to remediate all drift:', err);
      showToast(`Batch remediation failed: ${err.message || 'Server error'}`, 'error');
    } finally {
      setRemediatingAll(false);
    }
  };

  const filteredRows = rows.filter((row) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      (row.username && row.username.toLowerCase().includes(term)) ||
      (row.policy && row.policy.toLowerCase().includes(term)) ||
      (row.service && row.service.toLowerCase().includes(term)) ||
      (row.risk && row.risk.toLowerCase().includes(term))
    );
  });

  const exportCSV = () => {
    if (!filteredRows.length) return;
    const headers = ['username', 'policy', 'service', 'status', 'risk'];
    const csvContent =
      'data:text/csv;charset=utf-8,' +
      [headers.join(','), ...filteredRows.map((e) => headers.map((h) => `"${e[h] || ''}"`).join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', 'unused_permissions_report.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleInvestigateFromModal = (item) => {
    if (onNavigateToAssistant) {
      onNavigateToAssistant(
        `Analyze least-privilege drift for user '${item.username}' regarding policy '${item.policy || 'AdministratorAccess'}' and unused service '${item.service}'. How should I construct a tailored IAM policy to eliminate this excess privilege?`
      );
    }
  };

  const unusedCount = summary
    ? summary.unused_permissions_count
    : rows.filter((r) => r.status === 'NEVER USED').length;
  const highRiskDrift = summary
    ? summary.high_risk_admin_drift
    : rows.filter((r) => String(r.risk).includes('HIGH')).length;
  const usedCount = summary
    ? summary.used_permissions_count
    : rows.filter((r) => r.status === 'USED').length;

  return (
    <div className="space-y-8 animate-fadeIn pt-2 sm:pt-4">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display-hero text-3xl sm:text-display-hero text-primary uppercase tracking-tight drop-shadow-[0_0_15px_rgba(255,255,255,0.2)]">
            Least-Privilege <span className="text-primary-fixed">Drift Analyzer</span>
          </h1>
          <p className="font-body-md text-body-md text-on-surface-variant mt-1 max-w-2xl">
            Continuous auditing of IAM policies against AWS Access Advisor telemetry to detect and remediate over-provisioned access.
          </p>
        </div>

        <button
          onClick={handleRemediateAll}
          disabled={remediatingAll || rows.length === 0}
          className="bg-primary-fixed text-on-primary-fixed font-label-caps text-xs uppercase tracking-widest px-6 py-3 rounded flex items-center gap-2 hover:bg-primary hover:shadow-[0_0_20px_rgba(190,245,0,0.6)] transition-all duration-300 font-bold active:scale-95 disabled:opacity-50"
        >
          <span className={`material-symbols-outlined text-lg ${remediatingAll ? 'animate-spin' : ''}`}>
            {remediatingAll ? 'sync' : 'verified_user'}
          </span>
          {remediatingAll ? 'Remediating...' : 'Remediate All Drift'}
        </button>
      </div>

      {/* Toast Banner */}
      {toastMessage && (
        <div
          className={`p-4 rounded-lg border font-label-caps text-xs uppercase tracking-wider flex items-center justify-between gap-2 animate-fadeIn ${
            toastType === 'error'
              ? 'bg-error-container/20 border-error text-error shadow-[0_0_15px_rgba(255,180,171,0.3)]'
              : 'bg-primary-fixed/20 border-primary-fixed text-primary-fixed shadow-[0_0_15px_rgba(190,245,0,0.3)]'
          }`}
        >
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-base">
              {toastType === 'error' ? 'error' : 'check_circle'}
            </span>
            <span>{toastMessage}</span>
          </div>
          <button
            onClick={() => setToastMessage('')}
            className="text-on-surface-variant hover:text-on-surface p-1"
          >
            <span className="material-symbols-outlined text-sm">close</span>
          </button>
        </div>
      )}

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

      {/* Bento Grid Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
        {/* Main Metric Card: Total Unused Permissions (4 Cols) */}
        <div className="col-span-1 md:col-span-4 glass-panel rounded-lg p-6 relative overflow-hidden group hover:border-primary-fixed/50 transition-all duration-300">
          {/* Top Neon Accent Line */}
          <div className="absolute top-0 left-0 w-full h-1 bg-primary-fixed shadow-[0_0_12px_rgba(190,245,0,0.9)]"></div>
          <div className="flex flex-col h-full justify-between">
            <div>
              <h3 className="font-label-caps text-label-caps text-on-surface-variant uppercase tracking-widest flex items-center gap-2">
                <span className="material-symbols-outlined text-primary-fixed text-base">warning</span>
                Total Unused Permissions
              </h3>
              <div className="font-metric-lg text-metric-lg text-primary mt-4 tracking-wider flex items-baseline gap-2 glow-text-lime">
                {unusedCount.toLocaleString()}
                <span className="font-body-md text-sm text-secondary ml-1 flex items-center font-bold">
                  <span className="material-symbols-outlined text-xs">arrow_upward</span> 12%
                </span>
              </div>
            </div>
            <p className="font-body-md text-xs text-on-surface-variant/80 mt-6 border-t border-outline-variant/20 pt-4">
              Excess privilege gap identified across attached administrative and managed policies.
            </p>
          </div>
        </div>

        {/* Secondary Progress Cards (8 Cols) */}
        <div className="col-span-1 md:col-span-8 grid grid-cols-1 sm:grid-cols-2 gap-6">
          {/* High Risk Drift */}
          <div className="glass-panel rounded-lg p-6 border-l-4 border-secondary glow-pink relative overflow-hidden flex flex-col justify-between">
            <div>
              <h3 className="font-label-caps text-label-caps text-secondary uppercase tracking-widest">
                High Risk Admin Drift
              </h3>
              <div className="font-metric-md text-4xl text-primary mt-2 drop-shadow-[0_0_8px_rgba(255,46,159,0.7)]">
                {highRiskDrift}
              </div>
            </div>
            <div className="mt-4">
              <div className="flex justify-between text-xs font-label-caps text-on-surface-variant mb-1">
                <span>Exposure Level</span>
                <span className="text-[#FF2E9F]">99.7% Unused</span>
              </div>
              <div className="bg-surface-container-highest h-2 w-full rounded-full overflow-hidden">
                <div className="bg-[#FF2E9F] h-full w-[95%] shadow-[0_0_10px_#FF2E9F]"></div>
              </div>
            </div>
          </div>

          {/* Active / Used Permissions */}
          <div className="glass-panel rounded-lg p-6 border-l-4 border-primary-fixed glow-lime relative overflow-hidden flex flex-col justify-between">
            <div>
              <h3 className="font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest">
                Active / Used Services
              </h3>
              <div className="font-metric-md text-4xl text-primary mt-2 drop-shadow-[0_0_8px_rgba(190,245,0,0.7)]">
                {usedCount}
              </div>
            </div>
            <div className="mt-4">
              <div className="flex justify-between text-xs font-label-caps text-on-surface-variant mb-1">
                <span>Verified Activity</span>
                <span className="text-primary-fixed">Last Authenticated</span>
              </div>
              <div className="bg-surface-container-highest h-2 w-full rounded-full overflow-hidden">
                <div className="bg-primary-fixed h-full w-[35%] shadow-[0_0_10px_#bef500]"></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Detailed Audit Table */}
      <div className="glass-panel rounded-lg overflow-hidden border border-outline-variant/30 shadow-2xl">
        <div className="p-5 border-b border-outline-variant/30 flex justify-between items-center bg-surface-container/50">
          <div>
            <h3 className="font-headline-sm text-headline-sm text-primary uppercase tracking-wide flex items-center gap-2">
              <span className="material-symbols-outlined text-primary-fixed text-xl">policy</span>
              Granted-But-Not-Used Audit Log ({filteredRows.length} services)
            </h3>
          </div>
          <div className="flex gap-2">
            <button
              onClick={exportCSV}
              className="px-3.5 py-1.5 text-xs font-label-caps uppercase tracking-wider border border-primary-fixed/50 text-primary-fixed rounded hover:bg-primary-fixed hover:text-on-primary-fixed transition-colors flex items-center gap-1.5 shadow-[0_0_8px_rgba(190,245,0,0.2)] font-bold"
            >
              <span className="material-symbols-outlined text-sm">download</span>
              Export Audit CSV
            </button>
          </div>
        </div>

        <div className="w-full overflow-x-auto">
          <table className="w-full text-left border-collapse cyber-table font-body-md text-sm">
            <thead>
              <tr className="bg-surface-container-high/40 border-b-2 border-primary-fixed/40">
                <th className="p-4 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest">
                  IAM Identity / User
                </th>
                <th className="p-4 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest">
                  Attached Policy
                </th>
                <th className="p-4 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest">
                  Evaluated Service
                </th>
                <th className="p-4 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest">
                  Usage Status
                </th>
                <th className="p-4 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest">
                  Risk Level
                </th>
                <th className="p-4 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest text-right">
                  Action
                </th>
              </tr>
            </thead>
            <tbody className="text-on-surface divide-y divide-outline-variant/10">
              {loading ? (
                <tr>
                  <td colSpan="6" className="p-12 text-center text-primary-fixed font-mono text-sm">
                    <span className="material-symbols-outlined animate-spin text-2xl mb-2 block">sync</span>
                    Analyzing IAM permissions & Access Advisor telemetry...
                  </td>
                </tr>
              ) : filteredRows.length === 0 ? (
                <tr>
                  <td colSpan="6" className="p-12 text-center text-on-surface-variant font-mono text-sm">
                    No drift records found matching the filter.
                  </td>
                </tr>
              ) : (
                filteredRows.slice(0, 100).map((row, idx) => {
                  const isRevoked = remediated[idx];
                  const isHigh = String(row.risk).includes('HIGH');

                  return (
                    <tr
                      key={idx}
                      onClick={() => setSelectedItem(row)}
                      className={`hover:bg-surface-container-high/40 transition-colors group cursor-pointer ${
                        isRevoked ? 'opacity-40 bg-surface-container-lowest' : ''
                      }`}
                    >
                      {/* Identity */}
                      <td className="p-4 font-mono text-xs text-primary flex items-center gap-2">
                        <span className="material-symbols-outlined text-on-surface-variant text-sm">badge</span>
                        <span className="group-hover:text-primary-fixed transition-colors">{row.username}</span>
                      </td>

                      {/* Policy */}
                      <td className="p-4 font-mono text-xs text-on-surface-variant max-w-xs truncate">
                        {row.policy || 'AdministratorAccess'}
                      </td>

                      {/* Service */}
                      <td className="p-4 font-mono text-xs text-primary font-medium">
                        {row.service}
                      </td>

                      {/* Status */}
                      <td className="p-4">
                        {row.status === 'NEVER USED' ? (
                          <span className="text-error font-label-caps text-xs uppercase tracking-wider flex items-center gap-1 font-semibold">
                            <span className="w-1.5 h-1.5 rounded-full bg-error"></span>
                            NEVER USED
                          </span>
                        ) : (
                          <span className="text-primary-fixed font-label-caps text-xs uppercase tracking-wider flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-primary-fixed"></span>
                            USED
                          </span>
                        )}
                      </td>

                      {/* Risk */}
                      <td className="p-4">
                        {isHigh ? (
                          <span className="inline-flex px-2.5 py-1 bg-secondary/15 border border-secondary text-secondary font-label-caps text-xs uppercase tracking-wider rounded font-bold">
                            High Risk Drift
                          </span>
                        ) : (
                          <span className="inline-flex px-2.5 py-1 border border-primary-fixed text-primary-fixed font-label-caps text-xs uppercase tracking-wider rounded">
                            Medium
                          </span>
                        )}
                      </td>

                      {/* Action */}
                      <td className="p-4 text-right">
                        {isRevoked ? (
                          <span className="text-primary-fixed font-label-caps text-xs uppercase tracking-wider flex items-center justify-end gap-1 font-bold">
                            <span className="material-symbols-outlined text-sm">check_circle</span>
                            Remediated
                          </span>
                        ) : (
                          <button
                            onClick={(e) => handleRevoke(e, idx, row)}
                            disabled={remediatingRows[idx]}
                            className="text-primary-fixed hover:text-primary font-label-caps uppercase text-xs tracking-wider flex items-center gap-1 ml-auto px-2.5 py-1 rounded border border-transparent hover:border-primary-fixed/40 hover:bg-primary-fixed/10 transition-all opacity-80 group-hover:opacity-100 disabled:opacity-50"
                          >
                            <span
                              className={`material-symbols-outlined text-xs ${
                                remediatingRows[idx] ? 'animate-spin' : ''
                              }`}
                            >
                              {remediatingRows[idx] ? 'sync' : 'build'}
                            </span>
                            {remediatingRows[idx] ? 'Revoking...' : 'Revoke'}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {filteredRows.length > 100 && (
          <div className="p-4 border-t border-outline-variant/30 bg-surface-container/30 text-center font-label-caps text-xs text-on-surface-variant uppercase tracking-wider">
            Showing first 100 of {filteredRows.length} records. Use search to filter specific services.
          </div>
        )}
      </div>

      {/* Item Detail Modal */}
      {selectedItem && (
        <EventDetailModal
          item={selectedItem}
          type="Least-Privilege Drift Record"
          onClose={() => setSelectedItem(null)}
          onInvestigate={handleInvestigateFromModal}
        />
      )}
    </div>
  );
}
