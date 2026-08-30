import React from 'react';

export default function EventDetailModal({ item, type, onClose, onInvestigate }) {
  if (!item) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
      <div className="glass-panel w-full max-w-2xl rounded-xl border border-primary-fixed/40 shadow-[0_0_30px_rgba(190,245,0,0.25)] overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="p-5 border-b border-outline-variant/30 flex items-center justify-between bg-surface-container-low/80">
          <div className="flex items-center gap-3">
            <span className="material-symbols-outlined text-primary-fixed text-2xl">
              radar
            </span>
            <div>
              <h3 className="font-headline-sm text-lg text-primary uppercase tracking-wide">
                Security Telemetry Inspection
              </h3>
              <p className="font-label-caps text-[11px] text-on-surface-variant uppercase tracking-wider">
                Type: {type || 'Telemetry Record'} • Entity: {item.username || item.identity || 'AWS Resource'}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-on-surface-variant hover:text-primary hover:bg-surface-variant/50 rounded transition-colors"
          >
            <span className="material-symbols-outlined text-xl">close</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-5 overflow-y-auto font-body-md text-sm">
          {/* Key Attributes Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="p-3 rounded bg-surface-container-high/60 border border-outline-variant/30">
              <span className="font-label-caps text-[10px] text-on-surface-variant uppercase tracking-wider block">
                Target Identity / Principal
              </span>
              <span className="font-mono text-xs text-primary font-semibold block mt-1 break-all">
                {item.username || item.identity || 'N/A'}
              </span>
            </div>

            <div className="p-3 rounded bg-surface-container-high/60 border border-outline-variant/30">
              <span className="font-label-caps text-[10px] text-on-surface-variant uppercase tracking-wider block">
                Risk Classification
              </span>
              <span className="font-label-caps text-xs uppercase tracking-wider font-bold block mt-1 text-[#FF2E9F]">
                {item.risk_level || item.risk || 'INFORMATIONAL'}
              </span>
            </div>

            {item.event && (
              <div className="p-3 rounded bg-surface-container-high/60 border border-outline-variant/30">
                <span className="font-label-caps text-[10px] text-on-surface-variant uppercase tracking-wider block">
                  CloudTrail Event Action
                </span>
                <span className="font-mono text-xs text-primary-fixed block mt-1">
                  {item.event}
                </span>
              </div>
            )}

            {item.policy && (
              <div className="p-3 rounded bg-surface-container-high/60 border border-outline-variant/30">
                <span className="font-label-caps text-[10px] text-on-surface-variant uppercase tracking-wider block">
                  Associated IAM Policy
                </span>
                <span className="font-mono text-xs text-primary block mt-1 break-all">
                  {item.policy}
                </span>
              </div>
            )}

            {item.service && (
              <div className="p-3 rounded bg-surface-container-high/60 border border-outline-variant/30">
                <span className="font-label-caps text-[10px] text-on-surface-variant uppercase tracking-wider block">
                  AWS Service Namespace
                </span>
                <span className="font-mono text-xs text-primary-fixed block mt-1">
                  {item.service}
                </span>
              </div>
            )}

            {item.status && (
              <div className="p-3 rounded bg-surface-container-high/60 border border-outline-variant/30">
                <span className="font-label-caps text-[10px] text-on-surface-variant uppercase tracking-wider block">
                  Advisor Usage Status
                </span>
                <span className="font-mono text-xs text-secondary block mt-1 font-bold">
                  {item.status}
                </span>
              </div>
            )}

            {item.check_type && (
              <div className="p-3 rounded bg-surface-container-high/60 border border-outline-variant/30">
                <span className="font-label-caps text-[10px] text-on-surface-variant uppercase tracking-wider block">
                  Compliance Check Type
                </span>
                <span className="font-mono text-xs text-primary block mt-1">
                  {item.check_type}
                </span>
              </div>
            )}

            {item.detail && (
              <div className="p-3 rounded bg-surface-container-high/60 border border-outline-variant/30 sm:col-span-2">
                <span className="font-label-caps text-[10px] text-on-surface-variant uppercase tracking-wider block">
                  Telemetry Detail
                </span>
                <span className="font-mono text-xs text-primary block mt-1">
                  {item.detail}
                </span>
              </div>
            )}
          </div>

          {/* Raw JSON Payload */}
          <div>
            <span className="font-label-caps text-xs text-on-surface-variant uppercase tracking-wider mb-2 block flex items-center gap-1.5">
              <span className="material-symbols-outlined text-sm">code</span>
              Raw Telemetry Object
            </span>
            <pre className="bg-surface-container-lowest p-4 rounded border border-outline-variant/30 text-primary-fixed font-mono text-xs overflow-x-auto max-h-48">
              {JSON.stringify(item, null, 2)}
            </pre>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-outline-variant/30 bg-surface-container-low/80 flex items-center justify-between">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-label-caps uppercase tracking-wider border border-outline-variant/40 rounded hover:bg-surface-variant/40 transition-colors text-on-surface"
          >
            Close
          </button>

          <button
            onClick={() => {
              onInvestigate(item);
              onClose();
            }}
            className="px-4 py-2 bg-primary-fixed text-on-primary-fixed text-xs font-label-caps uppercase tracking-widest rounded hover:bg-primary transition-all font-bold flex items-center gap-2 shadow-[0_0_12px_rgba(190,245,0,0.4)]"
          >
            <span className="material-symbols-outlined text-base">smart_toy</span>
            Investigate with NIMORA
          </button>
        </div>
      </div>
    </div>
  );
}
