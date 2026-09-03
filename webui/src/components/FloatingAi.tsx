import { useState, useRef, useEffect } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Brain, MessageCircle, X, Send, Zap, ExternalLink, AlertTriangle, CheckCircle, Sparkles, Bug, Star, Cpu, Cloud } from 'lucide-react'
import clsx from 'clsx'
import { Button } from './UI'
import type { ChatResult, CvePocResult, AiExploitResult, LlmStatus } from '../types'
import api from '../api'

const quickActions = [
  { label: 'SQL injection test', q: 'How do I test for SQL injection? Give me steps and a PoC payload.' },
  { label: 'XSS bypass techniques', q: 'What are common XSS bypass techniques for WAF? List payloads.' },
  { label: 'LFI to RCE', q: 'How to escalate LFI to RCE? Show log poisoning and php wrapper methods.' },
  { label: 'SSRF exploitation', q: 'How to exploit SSRF to access cloud metadata and internal services?' },
  { label: 'JWT attack', q: 'List common JWT attacks and how to test for each one.' },
]

export default function FloatingAi() {
  const [open, setOpen] = useState(false)
  const [mode, setMode] = useState<'chat' | 'exploit' | 'cvepoc'>('chat')
  const [question, setQuestion] = useState('')
  const [chatHistory, setChatHistory] = useState<Array<{ q: string; a: string; llm?: boolean; model?: string }>>([])
  const [exploitVuln, setExploitVuln] = useState('')
  const [exploitTarget, setExploitTarget] = useState('')
  const [exploitResult, setExploitResult] = useState<AiExploitResult | null>(null)
  const [cveId, setCveId] = useState('')
  const [cveResult, setCveResult] = useState<CvePocResult | null>(null)
  const [llmMode, setLlmMode] = useState<'offline' | 'llm'>(() => {
    if (typeof window !== 'undefined' && window.localStorage.getItem('webforg_llm_mode') === 'llm') return 'llm'
    return 'offline'
  })
  const chatEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 100)
  }, [open])

  useEffect(() => {
    api.get<LlmStatus>('/ai/llm/status')
      .then((res) => {
        const mode = res.data.mode === 'llm' ? 'llm' : 'offline'
        setLlmMode(mode)
        try { window.localStorage.setItem('webforg_llm_mode', mode) } catch { /* ignore */ }
      })
      .catch(() => { /* keep current */ })
  }, [open])

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [chatHistory])

  const chatMutation = useMutation({
    mutationFn: async (q: string) => {
      const res = await api.post<ChatResult>('/ai/chat', { question: q, context: '' })
      return res.data
    },
  })

  const exploitMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post<AiExploitResult>('/ai/exploit', { vulnerability: exploitVuln, target: exploitTarget, details: '' })
      return res.data
    },
    onSuccess: (data) => setExploitResult(data),
  })

  const cveMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post<CvePocResult>('/ai/cve-poc', { cve_id: cveId.trim() })
      return res.data
    },
    onSuccess: (data) => setCveResult(data),
  })

  const handleSend = () => {
    if (!question.trim()) return
    const q = question.trim()
    chatMutation.mutate(q, {
      onSuccess: (data) => {
        setChatHistory((prev) => [...prev, { q, a: data.answer, llm: data.llm, model: data.model }])
        if (data.llm) setLlmMode('llm')
        setQuestion('')
      },
    })
  }

  return (
    <>
      {/* Floating button */}
      <button
        onClick={() => setOpen(!open)}
        className="fixed bottom-5 right-5 z-40 w-12 h-12 min-w-[48px] min-h-[48px] bg-webforge-600 hover:bg-webforge-500 text-white rounded-full shadow-2xl flex items-center justify-center transition-all hover:scale-105"
        aria-label="AI Assistant"
      >
        {open ? <X className="w-5 h-5" /> : <Brain className="w-5 h-5" />}
      </button>

      {/* Panel */}
      {open && (
        <div className="fixed bottom-20 right-5 z-40 w-[380px] max-w-[calc(100vw-2.5rem)] bg-gray-900/95 border border-gray-700/60 rounded-2xl shadow-2xl flex flex-col overflow-hidden backdrop-blur-md" style={{ maxHeight: 'min(600px, calc(100vh - 6rem))' }}>
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800/60 shrink-0">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-webforge-400" />
              <span className="font-semibold text-sm text-gray-200">AI Assistant</span>
              <span
                className={clsx(
                  'inline-flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded',
                  llmMode === 'llm'
                    ? 'bg-green-500/10 border border-green-500/20 text-green-400'
                    : 'bg-gray-800/60 border border-gray-700/40 text-gray-500',
                )}
                title={llmMode === 'llm' ? 'Cloud LLM enabled' : 'Offline rule-based AI (zero device load)'}
              >
                {llmMode === 'llm' ? <Cloud className="w-2.5 h-2.5" /> : <Cpu className="w-2.5 h-2.5" />}
                {llmMode === 'llm' ? 'LLM' : 'OFFLINE'}
              </span>
            </div>
            <div className="flex items-center gap-0.5">
              {[
                { id: 'chat' as const, label: 'Chat' },
                { id: 'cvepoc' as const, label: 'CVE PoC' },
                { id: 'exploit' as const, label: 'Exploit' },
              ].map((m) => (
                <button
                  key={m.id}
                  onClick={() => { setMode(m.id); setExploitResult(null); setCveResult(null) }}
                  className={clsx(
                    'px-2.5 py-1.5 text-xs rounded-lg transition-colors font-medium',
                    mode === m.id ? 'bg-webforge-500/15 text-webforge-400' : 'text-gray-500 hover:text-gray-300',
                  )}
                >
                  {m.label}
                </button>
              ))}
            </div>
          </div>

          {mode === 'chat' ? (
            <>
              <div className="flex-1 overflow-y-auto p-3 space-y-3 bg-gray-950/50">
                {chatHistory.length === 0 && (
                  <div className="text-center py-4">
                    <MessageCircle className="w-7 h-7 mx-auto mb-2 text-gray-700" />
                    <p className="text-xs text-gray-600 mb-3">Ask anything about security</p>
                    <div className="flex flex-wrap gap-1.5 justify-center">
                      {quickActions.map((a) => (
                        <button
                          key={a.label}
                          onClick={() => {
                            chatMutation.mutate(a.q, {
                              onSuccess: (data) => setChatHistory((prev) => [...prev, { q: a.q, a: data.answer, llm: data.llm, model: data.model }]),
                            })
                          }}
                          className="text-[10px] px-2 py-1.5 bg-gray-800/60 border border-gray-700/40 rounded-lg text-gray-400 hover:text-gray-200 transition-colors"
                        >
                          {a.label}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
                {chatHistory.map((entry, i) => (
                  <div key={i} className="space-y-2">
                    <div className="flex justify-end">
                      <div className="bg-webforge-500/10 border border-webforge-500/20 rounded-xl rounded-br-sm px-3 py-2 max-w-[85%]">
                        <p className="text-xs text-webforge-300">{entry.q}</p>
                      </div>
                    </div>
                    <div className="flex justify-start">
                      <div className="bg-gray-800/60 border border-gray-700/40 rounded-xl rounded-bl-sm px-3 py-2 max-w-[90%]">
                        {entry.llm && (
                          <span className="inline-flex items-center gap-1 text-[8px] text-green-400 bg-green-500/10 border border-green-500/20 rounded px-1 py-0.5 mb-1">
                            <Cloud className="w-2 h-2" /> {entry.model || 'LLM'}
                          </span>
                        )}
                        <div className="text-xs text-gray-300 whitespace-pre-wrap leading-relaxed">{entry.a}</div>
                      </div>
                    </div>
                  </div>
                ))}
                {chatMutation.isPending && (
                  <div className="flex justify-start">
                    <div className="bg-gray-800/60 border border-gray-700/40 rounded-xl rounded-bl-sm px-3 py-2">
                      <div className="flex items-center gap-2">
                        <div className="w-3 h-3 border-2 border-webforge-400 border-t-transparent rounded-full animate-spin" />
                        <span className="text-xs text-gray-400">Thinking...</span>
                      </div>
                    </div>
                  </div>
                )}
                <div ref={chatEndRef} />
              </div>

              <div className="px-3 py-2.5 border-t border-gray-800/60 flex gap-2 shrink-0">
                <input
                  ref={inputRef}
                  type="text"
                  value={question}
                  onChange={(e) => setQuestion(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && (e.preventDefault(), handleSend())}
                  placeholder="Ask a security question..."
                  className="flex-1 min-w-0 px-3 py-2 bg-gray-800/80 border border-gray-700/60 rounded-lg text-xs focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20 outline-none transition-colors"
                />
                <button onClick={handleSend} disabled={!question.trim() || chatMutation.isPending} className="p-2 min-w-[36px] min-h-[36px] bg-webforge-600 hover:bg-webforge-500 disabled:bg-gray-700 text-white rounded-lg flex items-center justify-center transition-colors">
                  <Send className="w-4 h-4" />
                </button>
              </div>
            </>
          ) : mode === 'cvepoc' ? (
            <div className="flex-1 overflow-y-auto p-3 space-y-3 bg-gray-950/50">
              <p className="text-[10px] text-gray-500">Find real public PoCs for any CVE (GitHub, Metasploit, ExploitDB, Nuclei).</p>
              <input type="text" value={cveId} onChange={(e) => setCveId(e.target.value)} placeholder="CVE-2021-44228" className="w-full px-3 py-2 bg-gray-800/80 border border-gray-700/60 rounded-lg text-xs focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20 outline-none transition-colors" />
              <Button onClick={() => cveMutation.mutate()} disabled={!cveId.trim() || cveMutation.isPending} loading={cveMutation.isPending} color="webforge" className="w-full text-xs py-2">
                <Bug className="w-3 h-3" /> Search PoCs
              </Button>
              {cveMutation.isError && <p className="text-xs text-red-400">{cveMutation.error.message}</p>}
              {cveResult && !cveResult.success && (
                <div className="flex items-center gap-2 text-xs text-yellow-400">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  {cveResult.error || 'CVE lookup failed'}
                </div>
              )}
              {cveResult?.success && (
                <div className="space-y-3">
                  {cveResult.errors && cveResult.errors.length > 0 && (
                    <div className="text-[9px] text-yellow-500/80">
                      {cveResult.partial ? 'Partial results — ' : ''}
                      {cveResult.errors.length} source(s) timed out; showing what came back.
                    </div>
                  )}
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono font-bold text-xs text-gray-100">{cveResult.cve_id}</span>
                    {cveResult.severity && (
                      <span className={clsx('text-[9px] px-2 py-0.5 rounded font-bold text-white', {
                        'bg-red-600': cveResult.severity.toUpperCase() === 'CRITICAL',
                        'bg-orange-600': cveResult.severity.toUpperCase() === 'HIGH',
                        'bg-yellow-600': cveResult.severity.toUpperCase() === 'MEDIUM',
                        'bg-cyan-600': cveResult.severity.toUpperCase() === 'LOW',
                      })}>{cveResult.severity.toUpperCase()}</span>
                    )}
                  </div>
                  <div className="grid grid-cols-3 gap-2">
                    {[['CVSS', cveResult.cvss_score], ['EPSS', cveResult.epss_score], ['KEV', cveResult.kev]].map(([label, value]) => (
                      <div key={label} className="bg-gray-800/50 rounded-lg px-2 py-1.5 text-center border border-gray-800/30">
                        <div className="text-[9px] text-gray-500">{label}</div>
                        <div className="text-xs text-gray-200 font-medium truncate">{value || 'N/A'}</div>
                      </div>
                    ))}
                  </div>
                  {cveResult.description && <p className="text-[10px] text-gray-400 leading-relaxed">{cveResult.description}</p>}
                  {cveResult.cwe && cveResult.cwe.length > 0 && (
                    <div className="flex items-center gap-1 flex-wrap">
                      {cveResult.cwe.map((c) => <span key={c} className="text-[9px] px-1.5 py-0.5 rounded bg-gray-800/60 border border-gray-700/40 font-mono text-cyan-400">{c}</span>)}
                    </div>
                  )}
                  {cveResult.kev === 'Yes' && (
                    <p className="text-[10px] text-red-300 flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> In CISA KEV catalog — actively exploited</p>
                  )}
                  {cveResult.sources?.github?.pocs && cveResult.sources.github.pocs.length > 0 && (
                    <div>
                      <p className="text-[10px] font-medium text-gray-300 mb-1">GitHub PoCs ({cveResult.sources.github.count})</p>
                      <div className="space-y-1">
                        {cveResult.sources.github.pocs.map((poc, i) => (
                          <div key={i} className="flex items-center gap-2 bg-gray-800/40 border border-gray-800/30 rounded-lg px-2 py-1.5">
                            <div className="flex-1 min-w-0">
                              <div className="text-[10px] font-mono text-gray-300 truncate">{poc.name || poc.html_url}</div>
                            </div>
                            {typeof poc.stargazers === 'number' && (
                              <span className="text-[9px] text-gray-400 flex items-center gap-0.5 shrink-0"><Star className="w-2.5 h-2.5 text-yellow-500" />{poc.stargazers}</span>
                            )}
                            {poc.html_url && (
                              <a href={poc.html_url} target="_blank" rel="noopener noreferrer" className="text-webforge-400 shrink-0"><ExternalLink className="w-3 h-3" /></a>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {cveResult.sources?.metasploit_exploitdb_nuclei && (
                    <div className="space-y-1">
                      {(() => {
                        const t = cveResult.sources!.metasploit_exploitdb_nuclei!
                        return [
                          t.metasploit && { name: 'Metasploit', cmd: t.metasploit.command },
                          t.exploitdb && { name: 'ExploitDB', cmd: t.exploitdb.command },
                          t.nuclei && { name: 'Nuclei', cmd: t.nuclei.command },
                        ].filter((x): x is { name: string; cmd: string } => Boolean(x)).map((x, i) => (
                          <div key={i} className="flex items-start gap-2 bg-gray-800/40 border border-gray-800/30 rounded-lg px-2 py-1.5">
                            <span className="text-[9px] px-1.5 py-0.5 rounded bg-webforge-500/10 text-webforge-400 font-bold shrink-0">{x.name}</span>
                            <code className="text-[9px] font-mono text-green-400 break-all">{x.cmd}</code>
                          </div>
                        ))
                      })()}
                    </div>
                  )}
                  {cveResult.remediation && (
                    <div className="bg-gray-800/40 border border-gray-800/30 rounded-lg px-2 py-1.5">
                      <p className="text-[9px] text-cyan-400 font-medium mb-0.5">Remediation</p>
                      <p className="text-[10px] text-gray-400">{cveResult.remediation}</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto p-3 space-y-3 bg-gray-950/50">
              <p className="text-[10px] text-gray-500">Run an exploit PoC against a target using the AI knowledge base.</p>
              <select value={exploitVuln} onChange={(e) => setExploitVuln(e.target.value)} className="w-full px-3 py-2 bg-gray-800/80 border border-gray-700/60 rounded-lg text-xs focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20 outline-none transition-colors">
                <option value="">Vulnerability...</option>
                <option value="sql_injection">SQL Injection</option>
                <option value="xss">Cross-Site Scripting</option>
                <option value="lfi">Local File Inclusion</option>
                <option value="rfi">Remote File Inclusion</option>
                <option value="ssti">SSTI</option>
                <option value="ssrf">SSRF</option>
                <option value="command_injection">Command Injection</option>
                <option value="xxe">XXE</option>
              </select>
              <input type="text" value={exploitTarget} onChange={(e) => setExploitTarget(e.target.value)} placeholder="Target URL" className="w-full px-3 py-2 bg-gray-800/80 border border-gray-700/60 rounded-lg text-xs focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20 outline-none transition-colors" />
              <Button onClick={() => exploitMutation.mutate()} disabled={!exploitVuln || !exploitTarget || exploitMutation.isPending} loading={exploitMutation.isPending} color="webforge" className="w-full text-xs py-2">
                <Zap className="w-3 h-3" /> Generate & Run PoC
              </Button>
              {exploitMutation.isError && <p className="text-xs text-red-400">{exploitMutation.error.message}</p>}
              {exploitMutation.data && (
                <div className="space-y-2">
                  <div className={clsx('flex items-center gap-2 text-xs font-medium', exploitMutation.data.success ? 'text-green-400' : 'text-yellow-400')}>
                    {exploitMutation.data.success ? <CheckCircle className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
                    {exploitMutation.data.success ? 'Module executed' : 'No module found — PoC shown below'}
                  </div>
                  {exploitMutation.data.poc_generated && (
                    <pre className="text-[10px] text-green-400 font-mono bg-gray-950/80 border border-gray-800/50 rounded-lg p-2 max-h-32 overflow-y-auto whitespace-pre-wrap break-words">{exploitMutation.data.poc_generated}</pre>
                  )}
                  {exploitMutation.data.execution_result && (
                    <pre className="text-[10px] text-gray-400 font-mono bg-gray-950/80 border border-gray-800/50 rounded-lg p-2 max-h-32 overflow-y-auto whitespace-pre-wrap break-words">{JSON.stringify(exploitMutation.data.execution_result, null, 2)}</pre>
                  )}
                </div>
              )}
            </div>
          )}

          <a href="/ai" className="flex items-center justify-center gap-1 px-3 py-2 border-t border-gray-800/60 text-[10px] text-gray-600 hover:text-gray-400 transition-colors shrink-0">
            <ExternalLink className="w-3 h-3" /> Full AI Helper page
          </a>
        </div>
      )}
    </>
  )
}
