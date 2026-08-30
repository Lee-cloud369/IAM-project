import React, { useState, useRef, useEffect } from 'react';
import { askAiAssistant } from '../services/api';

export default function AiAssistantPage({ initialQuery }) {
  const [messages, setMessages] = useState([
    {
      id: 1,
      sender: 'ai',
      text: "Analyzing live security telemetry across AWS CloudTrail, Access Advisor, and Credential reports. I have detected elevated administrative privileges and inactive permissions on several key identities.\n\nHow can I assist your investigation today?",
      chips: [
        { label: 'Summarize top risks', query: 'What are my top 3 security risks right now?' },
        { label: 'Unused admin check', query: 'Which users have unused AdministratorAccess permissions?' },
        { label: 'MFA compliance audit', query: 'What is our current MFA compliance status?' },
        { label: 'Draft Least-Privilege Policy', query: 'Draft a recommended least-privilege IAM policy based on actual usage logs.' },
      ],
      timestamp: '14:02 UTC',
    },
  ]);

  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);
  const [copiedId, setCopiedId] = useState(null);
  const messagesEndRef = useRef(null);
  const lastHandledQueryRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  const handleSendMessage = async (textToSend) => {
    const query = textToSend || inputText;
    if (!query.trim() || loading) return;

    const userMessage = {
      id: Date.now(),
      sender: 'user',
      text: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInputText('');
    setLoading(true);

    try {
      const data = await askAiAssistant(query);

      const aiResponse = {
        id: Date.now() + 1,
        sender: 'ai',
        text: data.response || 'I analyzed your security telemetry but received no response.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages((prev) => [...prev, aiResponse]);
    } catch (err) {
      console.error('AI chat failed:', err);
      const errorResponse = {
        id: Date.now() + 1,
        sender: 'ai',
        text: '⚠️ Unable to connect to the NIMORA AI backend service. Please ensure the FastAPI server is running at http://127.0.0.1:8000.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, errorResponse]);
    } finally {
      setLoading(false);
    }
  };

  // If redirected with an initial query from another page
  useEffect(() => {
    if (initialQuery && initialQuery.trim() && lastHandledQueryRef.current !== initialQuery) {
      lastHandledQueryRef.current = initialQuery;
      handleSendMessage(initialQuery);
    }
  }, [initialQuery]);

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleClearHistory = () => {
    setMessages([
      {
        id: Date.now(),
        sender: 'ai',
        text: "Intelligence session reset. Ready for new security investigation queries.",
        chips: [
          { label: 'Summarize top risks', query: 'What are my top 3 security risks right now?' },
          { label: 'Unused admin check', query: 'Which users have unused AdministratorAccess permissions?' },
          { label: 'MFA compliance audit', query: 'What is our current MFA compliance status?' },
        ],
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      },
    ]);
  };

  const handleCopy = (id, text) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="h-[calc(100vh-140px)] w-full flex flex-col glass-panel rounded-2xl overflow-hidden border border-outline-variant/30 shadow-2xl relative animate-fadeIn">
      {/* Top Header Bar */}
      <div className="h-16 border-b border-outline-variant/30 flex items-center px-6 sm:px-8 justify-between bg-surface-container-lowest/80 backdrop-blur-md shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-3 h-3 rounded-full bg-primary-fixed animate-pulse neon-glow-primary"></div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-label-caps text-xs sm:text-sm text-primary-fixed uppercase tracking-widest font-bold">
                NIMORA Cyber-Ops
              </span>
              <span className="hidden sm:inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-label-caps uppercase tracking-wider bg-primary-fixed/10 text-primary-fixed border border-primary-fixed/30 font-bold">
                ONLINE
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 sm:gap-5">
          <span className="font-label-caps text-[11px] text-on-surface-variant uppercase tracking-wider hidden md:block opacity-75">
            Model: Gemini 3.1 Flash Lite
          </span>
          <button
            onClick={handleClearHistory}
            title="Reset Chat Session"
            className="text-on-surface-variant hover:text-primary-fixed text-xs font-label-caps uppercase flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-outline-variant/30 hover:border-primary-fixed/50 hover:bg-primary-fixed/5 transition-all"
          >
            <span className="material-symbols-outlined text-base">restart_alt</span>
            <span className="hidden sm:inline">New Session</span>
          </button>
        </div>
      </div>

      {/* Main Chat Thread (ChatGPT-style Centered Stream) */}
      <div className="flex-1 overflow-y-auto px-4 py-6 sm:px-8 space-y-6 scroll-smooth">
        <div className="max-w-4xl mx-auto w-full space-y-6">
          <div className="text-center font-label-caps text-[11px] text-on-surface-variant opacity-60 my-2 uppercase tracking-widest flex items-center justify-center gap-2">
            <span className="w-8 h-[1px] bg-outline-variant/40"></span>
            <span>Security Intelligence Session Active • Telemetry Context Synchronized</span>
            <span className="w-8 h-[1px] bg-outline-variant/40"></span>
          </div>

          {messages.map((msg) => {
            const isAI = msg.sender === 'ai';

            return (
              <div
                key={msg.id}
                className={`flex gap-3 sm:gap-4 w-full ${
                  isAI ? 'items-start' : 'items-start justify-end'
                }`}
              >
                {/* AI Avatar */}
                {isAI && (
                  <div className="w-9 h-9 sm:w-10 sm:h-10 rounded-xl bg-surface-container-highest border border-primary-fixed flex items-center justify-center shrink-0 neon-glow-primary mt-1">
                    <span className="material-symbols-outlined text-primary-fixed text-xl">smart_toy</span>
                  </div>
                )}

                {/* Message Bubble Container */}
                <div
                  className={`w-full ${
                    isAI
                      ? 'max-w-[95%] sm:max-w-[88%]'
                      : 'max-w-[90%] sm:max-w-[78%] flex flex-col items-end'
                  }`}
                >
                  {/* Sender & Timestamp */}
                  <div
                    className={`font-label-caps text-[10px] uppercase tracking-wider mb-1.5 flex items-center gap-2 ${
                      isAI ? 'text-primary-fixed font-bold' : 'text-secondary font-bold'
                    }`}
                  >
                    <span>{isAI ? 'NIMORA AI' : 'You (SecAnalyst)'}</span>
                    <span className="text-on-surface-variant/50">• {msg.timestamp}</span>
                  </div>

                  {/* Message Content Bubble */}
                  <div
                    className={`p-4 sm:p-5 rounded-2xl text-sm sm:text-[15px] leading-relaxed transition-all ${
                      isAI
                        ? 'glass-panel rounded-tl-sm border-l-4 border-l-primary-fixed border border-outline-variant/40 text-on-surface shadow-lg'
                        : 'bg-surface-container-high/90 backdrop-blur-md rounded-tr-sm border border-secondary-container/40 text-on-surface shadow-md'
                    }`}
                  >
                    {/* 
                      SECURE CODING: OUTPUT ENCODING (XSS PREVENTION)
                      Explanation for Beginners:
                      - React renders {msg.text} as plain text by default, treating all characters literally.
                      - If an AI response contains malicious HTML or JavaScript (e.g. <script>alert(1)</script>),
                        React automatically escapes and converts those characters into harmless text entities.
                      - We explicitly DO NOT use dangerouslySetInnerHTML here, ensuring that any HTML/code
                        in the AI output can NEVER be executed by the user's browser.
                    */}
                    <div className="whitespace-pre-wrap font-body-md leading-relaxed select-text">
                      {msg.text}
                    </div>

                    {/* AI Message Footer: Action Chips & Copy Action */}
                    {isAI && (
                      <div className="mt-4 pt-3 border-t border-outline-variant/20 flex flex-wrap items-center justify-between gap-3">
                        {/* Action Suggestion Chips */}
                        {msg.chips && msg.chips.length > 0 && (
                          <div className="flex flex-wrap gap-2">
                            {msg.chips.map((chip, cIdx) => (
                              <button
                                key={cIdx}
                                onClick={() => handleSendMessage(chip.query)}
                                className="px-3 py-1.5 bg-surface-container-highest/80 border border-primary-fixed/40 text-primary-fixed text-xs font-label-caps uppercase tracking-wider hover:bg-primary-fixed hover:text-on-primary-fixed transition-all rounded-lg shadow-sm hover:shadow-[0_0_10px_rgba(190,245,0,0.4)] font-bold flex items-center gap-1.5 group"
                              >
                                <span className="material-symbols-outlined text-sm opacity-70 group-hover:opacity-100">bolt</span>
                                <span>{chip.label}</span>
                              </button>
                            ))}
                          </div>
                        )}

                        {/* Copy Response Button */}
                        <button
                          onClick={() => handleCopy(msg.id, msg.text)}
                          className="text-on-surface-variant hover:text-primary-fixed text-xs font-label-caps uppercase flex items-center gap-1 ml-auto transition-colors pt-1"
                          title="Copy response to clipboard"
                        >
                          <span className="material-symbols-outlined text-sm">
                            {copiedId === msg.id ? 'check' : 'content_copy'}
                          </span>
                          <span>{copiedId === msg.id ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                {/* User Avatar */}
                {!isAI && (
                  <div className="w-9 h-9 sm:w-10 sm:h-10 rounded-full border border-secondary-container bg-surface-variant flex items-center justify-center shrink-0 neon-glow-secondary mt-1">
                    <span className="material-symbols-outlined text-[#FF2E9F] text-xl">person</span>
                  </div>
                )}
              </div>
            );
          })}

          {/* Live Typing / Analyzing Indicator */}
          {loading && (
            <div className="flex items-start gap-3 sm:gap-4 max-w-4xl mx-auto w-full">
              <div className="w-9 h-9 sm:w-10 sm:h-10 rounded-xl bg-surface-container-highest border border-primary-fixed flex items-center justify-center shrink-0 neon-glow-primary">
                <span className="material-symbols-outlined text-primary-fixed text-xl animate-spin">sync</span>
              </div>
              <div className="glass-panel rounded-2xl rounded-tl-sm border-l-4 border-l-primary-fixed border border-outline-variant/40 p-4 shadow-lg flex items-center gap-3 text-primary-fixed text-xs sm:text-sm font-mono animate-pulse">
                <span className="w-2 h-2 rounded-full bg-primary-fixed animate-ping"></span>
                <span>NIMORA is analyzing security telemetry & synthesizing response...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>
      </div>

      {/* Fixed Bottom Input Area (ChatGPT-style) */}
      <div className="p-4 sm:p-5 border-t border-outline-variant/30 bg-surface-container-lowest/95 backdrop-blur-xl shrink-0">
        <div className="max-w-4xl mx-auto w-full">
          <div className="relative flex items-center bg-surface-container-low border border-outline-variant/60 rounded-2xl focus-within:border-primary-fixed focus-within:shadow-[0_0_15px_rgba(190,245,0,0.25)] transition-all p-1.5 sm:p-2">
            <span className="material-symbols-outlined text-primary-fixed/80 pl-3 text-xl pointer-events-none">
              terminal
            </span>
            <input
              type="text"
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={loading}
              placeholder="Ask NIMORA about IAM risks, unused roles, privilege escalation, or policy drafts..."
              className="w-full bg-transparent text-on-surface font-mono text-sm sm:text-base py-2.5 px-3 focus:outline-none placeholder:text-on-surface-variant/40"
            />
            <button
              onClick={() => handleSendMessage()}
              disabled={loading || !inputText.trim()}
              className="px-4 py-2.5 bg-primary-fixed text-on-primary-fixed font-label-caps text-xs uppercase tracking-widest rounded-xl hover:bg-primary-fixed-dim transition-all duration-200 flex items-center gap-1.5 font-bold shadow-[0_0_10px_rgba(190,245,0,0.4)] active:scale-95 disabled:opacity-30 disabled:pointer-events-none shrink-0"
            >
              <span>SEND</span>
              <span className="material-symbols-outlined text-sm font-bold">send</span>
            </button>
          </div>
          <div className="text-center mt-2.5 font-label-caps text-[10px] sm:text-[11px] text-on-surface-variant/60 uppercase tracking-widest">
            NIMORA Assistant • Grounded in live IAM security telemetry & AWS Access Advisor data
          </div>
        </div>
      </div>
    </div>
  );
}
