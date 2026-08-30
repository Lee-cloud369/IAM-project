import React, { useState, useEffect } from 'react';
import { getCredentialHygiene, remediateAccessKey, remediateMfaFlag } from '../services/api';
import EventDetailModal from '../components/EventDetailModal';

export default function CredentialHygienePage({ searchTerm, onNavigateToAssistant }) {
  const [rows, setRows] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [actionMessage, setActionMessage] = useState('');
  const [actionType, setActionType] = useState('success');
  const [enforcingMfa, setEnforcingMfa] = useState(false);
  const [deactivatingKeys, setDeactivatingKeys] = useState(false);
  const [actionLoadingRows, setActionLoadingRows] = useState({});
  const [remediatedRows, setRemediatedRows] = useState({});
  const [selectedItem, setSelectedItem] = useState(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const json = await getCredentialHygiene();
      setRows(json.data || []);
      setSummary(json.summary || null);
    } catch (err) {
      console.error('Failed to fetch hygiene report:', err);
      setError('Could not connect to FastAPI backend at http://127.0.0.1:8000/api/credential-hygiene');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const triggerAction = (msg, type = 'success') => {
    setActionMessage(msg);
    setActionType(type);
    setTimeout(() => setActionMessage(''), 5000);
  };

  const handleEnforceMfa = async () => {
    if (enforcingMfa) return;
    setEnforcingMfa(true);
    try {
      const resp = await remediateMfaFlag(null, true);
      triggerAction(
        resp?.message || 'Compliance notification logged and flagged for non-MFA identities (audit saved).',
        'success'
      );
    } catch (err) {
      console.error('MFA remediation failed:', err);
      triggerAction(`Failed to flag MFA compliance: ${err.message || 'Server error'}`, 'error');
    } finally {
      setEnforcingMfa(false);
    }
  };

  const handleDeactivateStaleKeys = async () => {
    if (deactivatingKeys) return;
    setDeactivatingKeys(true);
    try {
      const resp = await remediateAccessKey(null, null, 'Stale access key batch deactivation');
      triggerAction(
        resp?.message || 'Stale access keys successfully deactivated (Status=Inactive).',
        'success'
      );
    } catch (err) {
      console.error('Access key deactivation failed:', err);
      triggerAction(`Failed to deactivate stale keys: ${err.message || 'Server error'}`, 'error');
    } finally {
      setDeactivatingKeys(false);
    }
  };

  const handleRemediateRow = async (e, idx, row) => {
    e.stopPropagation();
    if (actionLoadingRows[idx] || remediatedRows[idx]) return;

    setActionLoadingRows((prev) => ({ ...prev, [idx]: true }));
    try {
      const isNoMfa = String(row.risk).includes('No MFA');
      let resp;
      if (isNoMfa) {
        resp = await remediateMfaFlag(row.username, false);
      } else {
        resp = await remediateAccessKey(row.username, row.detail, 'Credential hygiene rotation remediation');
      }
      setRemediatedRows((prev) => ({ ...prev, [idx]: true }));
      triggerAction(resp?.message || `Remediation logged for ${row.username}`, 'success');
    } catch (err) {
      console.error('Row remediation failed:', err);
      triggerAction(`Remediation failed for ${row.username}: ${err.message || 'Server error'}`, 'error');
    } finally {
      setActionLoadingRows((prev) => ({ ...prev, [idx]: false }));
    }
  };

  const filteredRows = rows.filter((row) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      (row.username && row.username.toLowerCase().includes(term)) ||
      (row.check_type && row.check_type.toLowerCase().includes(term)) ||
      (row.detail && row.detail.toLowerCase().includes(term)) ||
      (row.risk && row.risk.toLowerCase().includes(term))
    );
  });

  const exportCSV = () => {
    if (!filteredRows.length) return;
    const headers = ['username', 'check_type', 'detail', 'risk'];
    const csvContent =
      'data:text/csv;charset=utf-8,' +
      [headers.join(','), ...filteredRows.map((e) => headers.map((h) => `"${e[h] || ''}"`).join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', 'credential_hygiene_report.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleInvestigateFromModal = (item) => {
    if (onNavigateToAssistant) {
      onNavigateToAssistant(
        `Provide remediation guidance for credential posture issue: Identity '${item.username}' has check '${item.check_type}' with finding '${item.detail}' and risk '${item.risk}'. How should I securely resolve this?`
      );
    }
  };

  const noMfaCount = summary
    ? summary.users_without_mfa
    : rows.filter((r) => String(r.risk).includes('No MFA')).length;
  const staleKeyCount = summary
    ? summary.keys_needing_rotation
    : rows.filter((r) => String(r.risk).toLowerCase().includes('rotated')).length;

  return (
    <div className="space-y-8 animate-fadeIn pt-2 sm:pt-4">
      {/* Page Header */}
      <div>
        <h1 className="font-display-hero text-3xl sm:text-display-hero text-primary uppercase tracking-tight drop-shadow-[0_0_10px_rgba(255,255,255,0.2)]">
          Credential <span className="text-primary-fixed">Hygiene</span>
        </h1>
        <p className="font-body-md text-body-md text-on-surface-variant mt-2 max-w-3xl">
          Audit and enforce security standards for AWS IAM access keys, root account activity, and multi-factor authentication (MFA).
        </p>
      </div>

      {/* Action Notification Banner */}
      {actionMessage && (
        <div
          className={`p-4 rounded-lg border font-label-caps text-xs uppercase tracking-wider flex items-center justify-between gap-2 shadow-lg animate-fadeIn ${
            actionType === 'error'
              ? 'bg-error-container/20 border-error text-error shadow-[0_0_15px_rgba(255,180,171,0.3)]'
              : 'bg-primary-fixed/20 border-primary-fixed text-primary-fixed shadow-[0_0_15px_rgba(190,245,0,0.3)]'
          }`}
        >
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-base">
              {actionType === 'error' ? 'error' : 'check_circle'}
            </span>
            <span>{actionMessage}</span>
          </div>
          <button
            onClick={() => setActionMessage('')}
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

      {/* Top Row: Score & Key Metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Circular SVG Gauge Health Score (4 Cols) */}
        <div className="lg:col-span-4 glass-panel rounded-xl p-6 flex flex-col items-center justify-center relative overflow-hidden group hover:border-primary-fixed/50 transition-all duration-300">
          <div className="absolute inset-0 bg-primary-fixed/5 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"></div>
          <h3 className="font-label-caps text-xs uppercase text-on-surface-variant mb-6 tracking-widest absolute top-6 left-6 flex items-center gap-2">
            <span className="material-symbols-outlined text-primary-fixed text-sm">health_and_safety</span>
            Posture Health Score
          </h3>

          {/* Radial SVG Gauge */}
          <div className="relative w-48 h-48 rounded-full border-8 border-surface-container flex items-center justify-center shadow-[inset_0_0_20px_rgba(0,0,0,0.6)] mt-4">
            <svg className="absolute inset-0 w-full h-full -rotate-90 transform" viewBox="0 0 100 100">
              <circle cx="50" cy="50" fill="none" r="44" stroke="#282c1d" strokeWidth="8"></circle>
              {/* 78% score dasharray representation */}
              <circle
                className="drop-shadow-[0_0_10px_rgba(190,245,0,0.85)] transition-all duration-1000 ease-out"
                cx="50"
                cy="50"
                fill="none"
                r="44"
                stroke="#bef500"
                strokeDasharray="276"
                strokeDashoffset="60"
                strokeLinecap="round"
                strokeWidth="8"
              ></circle>
            </svg>
            <div className="text-center z-10">
              <span className="font-metric-lg text-6xl text-primary-fixed glow-text-lime block leading-none">
                78
              </span>
              <span className="font-label-caps text-xs text-on-surface-variant block mt-1 tracking-widest uppercase">
                / 100 Posture
              </span>
            </div>
          </div>
        </div>

        {/* 3 Metric Cards (8 Cols) */}
        <div className="lg:col-span-8 grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Card 1: Stale Keys */}
          <div className="glass-panel rounded-xl p-6 border-l-4 border-secondary glow-pink relative overflow-hidden flex flex-col justify-between">
            <div className="flex justify-between items-start">
              <h4 className="font-label-caps text-xs uppercase text-secondary tracking-widest">
                Stale Access Keys
              </h4>
              <span className="material-symbols-outlined text-[#FF2E9F]">key_off</span>
            </div>
            <div className="mt-4">
              <span className="font-metric-lg text-5xl text-primary drop-shadow-[0_0_10px_rgba(255,46,159,0.7)] leading-none">
                {staleKeyCount}
              </span>
              <div className="font-body-md text-xs text-secondary mt-1 font-semibold">
                &gt; 90 days rotation limit
              </div>
            </div>
          </div>

          {/* Card 2: Users without MFA */}
          <div className="glass-panel rounded-xl p-6 border-l-4 border-primary-fixed glow-lime relative overflow-hidden flex flex-col justify-between">
            <div className="flex justify-between items-start">
              <h4 className="font-label-caps text-xs uppercase text-primary-fixed tracking-widest">
                Users Without MFA
              </h4>
              <span className="material-symbols-outlined text-primary-fixed">lock_open</span>
            </div>
            <div className="mt-4">
              <span className="font-metric-lg text-5xl text-primary glow-text-lime leading-none">
                {noMfaCount}
              </span>
              <div className="font-body-md text-xs text-primary-fixed mt-1 font-semibold">
                Critical Compliance Risk
              </div>
            </div>
          </div>

          {/* Card 3: Root Account Posture */}
          <div className="glass-panel rounded-xl p-6 border-l-4 border-tertiary-fixed relative overflow-hidden flex flex-col justify-between">
            <div className="flex justify-between items-start">
              <h4 className="font-label-caps text-xs uppercase text-tertiary-fixed tracking-widest">
                Root Account Activity
              </h4>
              <span className="material-symbols-outlined text-tertiary-fixed">admin_panel_settings</span>
            </div>
            <div className="mt-4">
              <span className="font-metric-md text-2xl text-primary leading-tight block">
                Audited
              </span>
              <div className="font-body-md text-xs text-on-surface-variant mt-1">
                {summary && summary.root_account_status ? summary.root_account_status : 'Last logged July 2026'}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Area: Table & Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Audited Identities Table (9 Cols) */}
        <div className="lg:col-span-9 glass-panel rounded-xl overflow-hidden flex flex-col border border-outline-variant/30 shadow-2xl">
          <div className="p-5 border-b border-outline-variant/30 flex justify-between items-center bg-surface-container-high/30">
            <h3 className="font-headline-sm text-headline-sm text-primary uppercase flex items-center gap-2">
              <span className="material-symbols-outlined text-primary-fixed text-xl">verified</span>
              Audited Identities & Credential Report
            </h3>
            <span className="font-label-caps text-xs text-on-surface-variant uppercase tracking-wider hidden sm:block">
              {filteredRows.length} findings • Click row to inspect
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse cyber-table font-body-md text-sm">
              <thead>
                <tr className="bg-surface-container-high/50 border-b-2 border-primary-fixed/40">
                  <th className="py-3.5 px-5 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest">
                    Identity / Account
                  </th>
                  <th className="py-3.5 px-5 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest">
                    Check Type
                  </th>
                  <th className="py-3.5 px-5 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest">
                    Telemetry Detail
                  </th>
                  <th className="py-3.5 px-5 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest">
                    Risk Assessment
                  </th>
                  <th className="py-3.5 px-5 font-label-caps text-label-caps text-primary-fixed uppercase tracking-widest text-right">
                    Action
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-outline-variant/10 text-on-surface">
                {loading ? (
                  <tr>
                    <td colSpan="5" className="p-10 text-center text-primary-fixed font-mono text-sm">
                      <span className="material-symbols-outlined animate-spin text-2xl mb-2 block">sync</span>
                      Evaluating MFA devices and credential rotation reports...
                    </td>
                  </tr>
                ) : filteredRows.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="p-10 text-center text-on-surface-variant font-mono text-sm">
                      No credential records found.
                    </td>
                  </tr>
                ) : (
                  filteredRows.map((row, idx) => {
                    const isNoMfa = String(row.risk).includes('No MFA');
                    const isStale = String(row.risk).toLowerCase().includes('rotated');
                    const isRoot = row.username === '<root_account>';
                    const isRowRemediated = remediatedRows[idx];

                    return (
                      <tr
                        key={idx}
                        onClick={() => setSelectedItem(row)}
                        className={`hover:bg-surface-variant/30 cursor-pointer transition-colors group ${
                          isRowRemediated ? 'opacity-50 bg-surface-container-lowest' : ''
                        }`}
                      >
                        <td className="py-3.5 px-5 font-mono text-xs text-primary flex items-center gap-2.5">
                          <span className="material-symbols-outlined text-on-surface-variant text-base">
                            {isRoot ? 'manage_accounts' : 'person'}
                          </span>
                          <span className="font-semibold group-hover:text-primary-fixed transition-colors">
                            {row.username}
                          </span>
                        </td>

                        <td className="py-3.5 px-5 font-mono text-xs text-on-surface-variant">
                          {row.check_type}
                        </td>

                        <td className="py-3.5 px-5 font-mono text-xs text-primary">
                          {row.detail}
                        </td>

                        <td className="py-3.5 px-5">
                          {isNoMfa ? (
                            <span className="inline-flex px-2.5 py-1 bg-error text-on-error font-label-caps text-xs uppercase tracking-wider rounded font-bold shadow-[0_0_8px_rgba(255,180,171,0.6)]">
                              Critical - No MFA
                            </span>
                          ) : isStale ? (
                            <span className="inline-flex px-2.5 py-1 bg-secondary-container text-white font-label-caps text-xs uppercase tracking-wider rounded font-semibold shadow-[0_0_8px_rgba(224,0,136,0.5)]">
                              Rotate (90+ Days)
                            </span>
                          ) : (
                            <span className="inline-flex px-2.5 py-1 border border-primary-fixed text-primary-fixed font-label-caps text-xs uppercase tracking-wider rounded">
                              {row.risk || 'OK'}
                            </span>
                          )}
                        </td>

                        {/* Action Column */}
                        <td className="py-3.5 px-5 text-right">
                          {isRowRemediated ? (
                            <span className="text-primary-fixed font-label-caps text-xs uppercase tracking-wider flex items-center justify-end gap-1 font-bold">
                              <span className="material-symbols-outlined text-sm">check_circle</span>
                              Remediated
                            </span>
                          ) : isNoMfa ? (
                            <button
                              onClick={(e) => handleRemediateRow(e, idx, row)}
                              disabled={actionLoadingRows[idx]}
                              className="text-primary-fixed hover:text-primary font-label-caps uppercase text-xs tracking-wider inline-flex items-center gap-1 px-2.5 py-1 rounded border border-transparent hover:border-primary-fixed/40 hover:bg-primary-fixed/10 transition-all opacity-80 group-hover:opacity-100 disabled:opacity-50"
                            >
                              <span
                                className={`material-symbols-outlined text-xs ${
                                  actionLoadingRows[idx] ? 'animate-spin' : ''
                                }`}
                              >
                                {actionLoadingRows[idx] ? 'sync' : 'notification_important'}
                              </span>
                              {actionLoadingRows[idx] ? 'Flagging...' : 'Flag Non-MFA'}
                            </button>
                          ) : isStale ? (
                            <button
                              onClick={(e) => handleRemediateRow(e, idx, row)}
                              disabled={actionLoadingRows[idx]}
                              className="text-error hover:text-error-container font-label-caps uppercase text-xs tracking-wider inline-flex items-center gap-1 px-2.5 py-1 rounded border border-transparent hover:border-error/40 hover:bg-error/10 transition-all opacity-80 group-hover:opacity-100 disabled:opacity-50"
                            >
                              <span
                                className={`material-symbols-outlined text-xs ${
                                  actionLoadingRows[idx] ? 'animate-spin' : ''
                                }`}
                              >
                                {actionLoadingRows[idx] ? 'sync' : 'key_off'}
                              </span>
                              {actionLoadingRows[idx] ? 'Deactivating...' : 'Deactivate Key'}
                            </button>
                          ) : (
                            <span className="text-on-surface-variant/40 font-mono text-xs">-</span>
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

        {/* Quick Actions Panel (3 Cols) */}
        <div className="lg:col-span-3 flex flex-col gap-4">
          <div className="glass-panel rounded-xl p-5 border border-outline-variant/30 h-full flex flex-col shadow-2xl">
            <h3 className="font-headline-sm text-headline-sm text-primary uppercase mb-6 flex items-center gap-2">
              <span className="material-symbols-outlined text-primary-fixed">bolt</span>
              Quick Actions
            </h3>

            <div className="flex flex-col gap-4 flex-1">
              <button
                onClick={handleEnforceMfa}
                disabled={enforcingMfa}
                className="group w-full py-3 px-4 flex items-center justify-between border border-primary-fixed/50 bg-primary-fixed/10 hover:bg-primary-fixed hover:text-on-primary-container transition-all duration-300 rounded text-primary-fixed font-label-caps text-xs uppercase tracking-wider font-bold shadow-[0_0_10px_rgba(190,245,0,0.2)] disabled:opacity-50"
              >
                <span className="flex items-center gap-2">
                  <span className={`material-symbols-outlined text-base ${enforcingMfa ? 'animate-spin' : ''}`}>
                    {enforcingMfa ? 'sync' : 'shield_lock'}
                  </span>
                  {enforcingMfa ? 'Flagging Non-MFA Users...' : 'Flag Non-MFA (Audit)'}
                </span>
                <span className="material-symbols-outlined text-sm group-hover:translate-x-1 transition-transform">
                  arrow_forward
                </span>
              </button>

              <button
                onClick={handleDeactivateStaleKeys}
                disabled={deactivatingKeys}
                className="group w-full py-3 px-4 flex items-center justify-between border border-error/50 bg-error/10 hover:bg-error hover:text-on-error transition-all duration-300 rounded text-error font-label-caps text-xs uppercase tracking-wider font-bold disabled:opacity-50"
              >
                <span className="flex items-center gap-2">
                  <span className={`material-symbols-outlined text-base ${deactivatingKeys ? 'animate-spin' : ''}`}>
                    {deactivatingKeys ? 'sync' : 'autorenew'}
                  </span>
                  {deactivatingKeys ? 'Deactivating Stale Keys...' : 'Deactivate Stale Keys'}
                </span>
                <span className="material-symbols-outlined text-sm group-hover:translate-x-1 transition-transform">
                  arrow_forward
                </span>
              </button>

              <div className="mt-auto pt-6">
                <button
                  onClick={exportCSV}
                  className="w-full py-2.5 px-4 flex items-center justify-center gap-2 text-on-surface-variant hover:text-primary transition-colors font-label-caps text-xs uppercase tracking-wider border border-outline-variant/40 rounded hover:bg-surface-variant/50 font-bold"
                >
                  <span className="material-symbols-outlined text-base">download</span>
                  Export Audit Report
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Item Detail Modal */}
      {selectedItem && (
        <EventDetailModal
          item={selectedItem}
          type="Credential Hygiene Finding"
          onClose={() => setSelectedItem(null)}
          onInvestigate={handleInvestigateFromModal}
        />
      )}
    </div>
  );
}
