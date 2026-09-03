import { useState, useEffect } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Brain, Upload, MessageCircle, Zap, FileText, AlertTriangle, CheckCircle, ExternalLink, ChevronRight, Bug, Star, ShieldCheck, Cpu, Cloud } from 'lucide-react'
import { PageHeader, Card, Input, Button, Spinner } from '../components/UI'
import { SeverityBadge } from '../features/common/badges'
import { severityClassBorder, severitySolid } from '../utils/colors'
import { getErrorMessage } from '../utils/error'
import type { ChatResult, CvePocResult, LlmStatus, AiAnalysisResult, AiExploitResult } from '../types'
import api from '../api'

export default function AiHelper() {
  const [tab, setTab] = useState<'analyze' | 'chat' | 'exploit' | 'cvepoc'>('analyze')
  const [reportText, setReportText] = useState('')
  const [chatQuestion, setChatQuestion] = useState('')
  const [chatHistory, setChatHistory] = useState<Array<{ q: string; a: string; llm?: boolean; model?: string }>>([])
  const [exploitVuln, setExploitVuln] = useState('')
  const [exploitTarget, setExploitTarget] = useState('')
  const [exploitDetails, setExploitDetails] = useState('')
  const [cveId, setCveId] = useState('')
  const [llmStatus, setLlmStatus] = useState<LlmStatus | null>(null)

  useEffect(() => {
    api.get<LlmStatus>('/ai/llm/status')
      .then((res) => setLlmStatus(res.data))
      .catch(() => setLlmStatus({ configured: false, model: null, mode: 'offline' }))
  }, [])

  const analyzeMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post<AiAnalysisResult>('/ai/analyze', { report: reportText, format: 'auto' })
      return res.data
    },
  })

  const chatMutation = useMutation({
    mutationFn: async (question: string) => {
      const res = await api.post<ChatResult>('/ai/chat', { question, context: '' })
      return res.data
    },
  })

  const exploitMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post<AiExploitResult>('/ai/exploit', { vulnerability: exploitVuln, target: exploitTarget, details: exploitDetails })
      return res.data
    },
  })

  const cvePocMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post<CvePocResult>('/ai/cve-poc', { cve_id: cveId.trim() })
      return res.data
    },
  })

  const handleChatSend = () => {
    if (!chatQuestion.trim()) return
    chatMutation.mutate(chatQuestion.trim(), {
      onSuccess: (data) => {
        setChatHistory((prev) => [...prev, { q: chatQuestion.trim(), a: data.answer, llm: data.llm, model: data.model }])
        setChatQuestion('')
      },
    })
  }

  const tabs = [
    { id: 'analyze' as const, label: 'Analyze Report', icon: FileText },
    { id: 'chat' as const, label: 'AI Chat', icon: MessageCircle },
    { id: 'cvepoc' as const, label: 'CVE PoC', icon: Bug },
    { id: 'exploit' as const, label: 'Exploit PoC', icon: Zap },
  ]

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader
        title="AI Security Helper"
        subtitle="Analyze reports, ask security questions, and generate exploits with AI reasoning"
        icon={<Brain className="w-8 h-8" />}
        color="webforge"
      >
        <div className="flex gap-2 flex-wrap items-center">
          {llmStatus && (
            <span
              className={`flex items-center gap-1.5 px-3 py-2 min-h-[44px] rounded-lg border text-xs font-medium ${
                llmStatus.configured
                  ? 'bg-green-900/20 border-green-800/40 text-green-400'
                  : 'bg-gray-800 border-gray-700 text-gray-400'
              }`}
              title={llmStatus.configured
                ? 'Cloud LLM enabled — answers use the configured model'
                : 'No LLM configured — running offline rule-based engine (zero device load)'}
            >
              {llmStatus.configured ? <Cloud className="w-4 h-4" /> : <Cpu className="w-4 h-4" />}
              {llmStatus.configured ? `LLM: ${llmStatus.model}` : 'Offline (rule-based)'}
            </span>
          )}
          {tabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 px-4 py-3 min-h-[44px] rounded-lg text-sm font-medium transition-colors ${
                tab === t.id ? 'bg-webforge-600/20 text-webforge-400 border border-webforge-600/30' : 'bg-gray-800 text-gray-400 border border-gray-700 hover:border-gray-600'
              }`}
            >
              <t.icon className="w-4 h-4" />
              {t.label}
            </button>
          ))}
        </div>
      </PageHeader>

      {/* Tab: Analyze Report */}
      {tab === 'analyze' && (
        <div className="space-y-4">
          <Card>
            <h3 className="text-sm font-semibold text-gray-300 mb-3">Import Report</h3>
            <p className="text-xs text-gray-500 mb-3">Paste a Burp Suite XML, ZAP JSON report, or raw vulnerability description.</p>
            <textarea
              value={reportText}
              onChange={(e) => setReportText(e.target.value)}
              placeholder={`Paste report content here...

Try pasting a description like:
"SQL injection found in login.php with error-based detection. XSS vulnerability in search parameter."
Or paste an actual Burp/ZAP report.`}
              className="w-full h-48 px-4 py-3 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm font-mono text-gray-300 placeholder-gray-600 focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20 outline-none transition-colors resize-y"
              spellCheck={false}
            />
            <Button
              onClick={() => analyzeMutation.mutate()}
              disabled={!reportText.trim() || analyzeMutation.isPending}
              loading={analyzeMutation.isPending}
              className="mt-3"
              color="webforge"
            >
              <Upload className="w-4 h-4 mr-1" /> Analyze
            </Button>
          </Card>

          {analyzeMutation.isError && (
            <Card className="border-red-800">
              <div className="text-sm text-red-400">{getErrorMessage(analyzeMutation.error)}</div>
            </Card>
          )}

          {analyzeMutation.isPending && <Spinner text="Analyzing report with AI..." color="webforge" />}

          {analyzeMutation.data && (
            <div className="space-y-4">
              <Card>
                <h3 className="text-sm font-semibold text-gray-300 mb-3">Summary</h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="bg-gray-800/60 rounded-lg px-3 py-2 text-center">
                    <div className="text-lg font-bold text-white">{analyzeMutation.data.summary.total_findings}</div>
                    <div className="text-[10px] text-gray-400">Total Findings</div>
                  </div>
                  {Object.entries(analyzeMutation.data.summary.severity_breakdown).map(([sev, count]) => (
                    <div key={sev} className={`${severityClassBorder[sev] || 'text-gray-400 bg-gray-800/60'} rounded-lg px-3 py-2 text-center border`}>
                      <div className="text-lg font-bold">{count}</div>
                      <div className="text-[10px] opacity-75">{sev}</div>
                    </div>
                  ))}
                </div>
              </Card>

              {analyzeMutation.data.ai_insights && (
                <Card className="border-webforge-800/30">
                  <div className="flex items-center gap-1.5 text-[10px] text-webforge-400 font-medium mb-2">
                    {analyzeMutation.data.llm?.configured ? <Cloud className="w-3 h-3" /> : <Brain className="w-3 h-3" />}
                    AI Insights {analyzeMutation.data.llm?.configured ? `(${analyzeMutation.data.llm.model})` : ''}
                  </div>
                  <div className="text-xs text-gray-300 whitespace-pre-wrap leading-relaxed">{analyzeMutation.data.ai_insights}</div>
                </Card>
              )}

              {analyzeMutation.data.findings.map((f, i) => (
                <Card key={i}>
                  <div className="flex items-start gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className="font-semibold text-gray-200 text-sm">{f.label}</span>
                        <SeverityBadge severity={f.severity} variant="solid" size="xs" />
                        {f.cwe && <span className="text-[10px] font-mono text-gray-500">{f.cwe}</span>}
                      </div>
                      <p className="text-xs text-gray-400 mb-2">{f.description}</p>
                      <div className="bg-gray-950/50 border border-gray-800 rounded-lg p-3 mb-2">
                        <div className="flex items-center gap-1.5 text-[10px] text-webforge-400 font-medium mb-1.5">
                          <Zap className="w-3 h-3" /> PoC
                        </div>
                        <pre className="text-xs text-green-400 font-mono whitespace-pre-wrap break-words">{f.poc}</pre>
                      </div>
                      <div className="bg-gray-950/50 border border-gray-800 rounded-lg p-3">
                        <div className="flex items-center gap-1.5 text-[10px] text-cyan-400 font-medium mb-1.5">
                          <CheckCircle className="w-3 h-3" /> Remediation
                        </div>
                        <p className="text-xs text-gray-400">{f.remediation}</p>
                      </div>
                      {f.module && (
                        <div className="flex items-center gap-2 mt-2">
                          <span className="text-[10px] text-gray-600">Module:</span>
                          <code className="text-[10px] font-mono text-gray-500">{f.module}</code>
                        </div>
                      )}
                    </div>
                  </div>
                </Card>
              ))}

              {analyzeMutation.data.findings.length === 0 && (
                <Card>
                  <div className="flex items-center gap-3 text-yellow-400">
                    <AlertTriangle className="w-5 h-5 shrink-0" />
                    <div>
                      <p className="text-sm font-medium">No specific vulnerabilities identified</p>
                      <p className="text-xs text-gray-500 mt-1">The report did not match known vulnerability patterns. Try pasting more detailed findings.</p>
                    </div>
                  </div>
                </Card>
              )}
            </div>
          )}
        </div>
      )}

      {/* Tab: AI Chat */}
      {tab === 'chat' && (
        <div className="space-y-4">
          <Card className="p-0 overflow-hidden">
            <div className="px-4 py-2.5 border-b border-gray-800 flex items-center gap-2">
              <Brain className="w-4 h-4 text-webforge-400" />
              <span className="text-sm font-medium">Security Assistant</span>
            </div>
            <div className="h-80 overflow-y-auto p-4 space-y-4 bg-gray-950/50">
              {chatHistory.length === 0 && (
                <div className="text-center py-8">
                  <MessageCircle className="w-8 h-8 mx-auto mb-2 text-gray-700" />
                  <p className="text-sm text-gray-600">Ask anything about security vulnerabilities, exploitation, or remediation.</p>
                  <div className="flex flex-wrap gap-2 justify-center mt-4">
                    {[
                      'How do I exploit SQL injection?',
                      'What is the difference between LFI and RFI?',
                      'How to prevent XSS attacks?',
                      'Explain SSRF with example',
                      'How to escalate from RCE to full compromise?',
                    ].map((q) => (
                      <button
                        key={q}
                        onClick={() => {
                          setChatQuestion(q)
                          chatMutation.mutate(q, {
                            onSuccess: (data) => {
                              setChatHistory((prev) => [...prev, { q, a: data.answer, llm: data.llm, model: data.model }])
                              setChatQuestion('')
                            },
                          })
                        }}
                        className="text-xs px-3 py-2 bg-gray-800/80 border border-gray-700/60 rounded-lg text-gray-400 hover:text-gray-200 hover:border-gray-600 transition-colors"
                      >
                        {q}
                      </button>
                    ))}
                  </div>
                </div>
              )}
              {chatHistory.map((entry, i) => (
                <div key={i} className="space-y-3">
                  <div className="flex justify-end">
                    <div className="bg-webforge-600/20 border border-webforge-600/30 rounded-xl rounded-br-sm px-4 py-2.5 max-w-[80%]">
                      <p className="text-sm text-webforge-300">{entry.q}</p>
                    </div>
                  </div>
                  <div className="flex justify-start">
                    <div className="bg-gray-800/80 border border-gray-700/60 rounded-xl rounded-bl-sm px-4 py-2.5 max-w-[85%]">
                      {entry.llm && (
                        <span className="inline-flex items-center gap-1 text-[9px] text-green-400 bg-green-900/20 border border-green-800/40 rounded px-1.5 py-0.5 mb-1.5">
                          <Cloud className="w-2.5 h-2.5" /> {entry.model || 'LLM'}
                        </span>
                      )}
                      <div className="text-sm text-gray-300 whitespace-pre-wrap leading-relaxed">{entry.a}</div>
                    </div>
                  </div>
                </div>
              ))}
              {chatMutation.isPending && (
                <div className="flex justify-start">
                  <div className="bg-gray-800/80 border border-gray-700/60 rounded-xl rounded-bl-sm px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 border-2 border-webforge-400 border-t-transparent rounded-full animate-spin" />
                      <span className="text-sm text-gray-400">Thinking...</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
            <div className="px-4 py-2.5 border-t border-gray-800 flex gap-2">
              <input
                type="text"
                value={chatQuestion}
                onChange={(e) => setChatQuestion(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && (e.preventDefault(), handleChatSend())}
                placeholder="Ask a security question..."
                className="flex-1 min-w-0 px-3 py-3 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20 outline-none transition-colors"
              />
              <Button onClick={handleChatSend} disabled={!chatQuestion.trim() || chatMutation.isPending} loading={chatMutation.isPending} className="min-h-[44px]">Send</Button>
            </div>
          </Card>
        </div>
      )}

      {/* Tab: CVE PoC */}
      {tab === 'cvepoc' && (
        <div className="space-y-4">
          <Card>
            <h3 className="text-sm font-semibold text-gray-300 mb-3">CVE → PoC Intelligence</h3>
            <p className="text-xs text-gray-500 mb-4">Search real public exploits for a CVE ID from GitHub, Metasploit, ExploitDB, Nuclei, plus CVSS/EPSS/KEV intel via the CVE2PoC engine.</p>
            <div className="flex flex-col sm:flex-row gap-3">
              <Input
                label="CVE ID"
                value={cveId}
                onChange={(e) => setCveId(e.target.value)}
                placeholder="CVE-2021-44228"
                className="sm:max-w-xs"
              />
              <div className="sm:self-end">
                <Button
                  onClick={() => cvePocMutation.mutate()}
                  disabled={!cveId.trim() || cvePocMutation.isPending}
                  loading={cvePocMutation.isPending}
                  color="webforge"
                  className="min-h-[44px]"
                >
                  <Bug className="w-4 h-4 mr-1" /> Search PoCs
                </Button>
              </div>
            </div>
          </Card>

          {cvePocMutation.isError && (
            <Card className="border-red-800">
              <div className="text-sm text-red-400">{getErrorMessage(cvePocMutation.error)}</div>
            </Card>
          )}

          {cvePocMutation.isPending && <Spinner text="Querying CVE2PoC engine (GitHub, NVD, ExploitDB, Metasploit, Nuclei)..." color="webforge" />}

          {cvePocMutation.data && !cvePocMutation.data.success && (
            <Card className="border-yellow-700">
              <div className="flex items-center gap-3 text-yellow-400">
                <AlertTriangle className="w-5 h-5 shrink-0" />
                <div>
                  <p className="text-sm font-medium">CVE lookup failed</p>
                  <p className="text-xs text-gray-400 mt-1">{cvePocMutation.data.error || 'Unknown error'}</p>
                </div>
              </div>
            </Card>
          )}

          {cvePocMutation.data?.success && (
            <div className="space-y-4">
              <Card>
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div>
                    <h3 className="font-mono font-bold text-gray-100">{cvePocMutation.data.cve_id}</h3>
                    {cvePocMutation.data.description && (
                      <p className="text-xs text-gray-400 mt-2 max-w-2xl">{cvePocMutation.data.description}</p>
                    )}
                  </div>
                  {cvePocMutation.data.severity && (
                    <span className={`text-[11px] px-2.5 py-1 rounded font-bold text-white ${severitySolid[cvePocMutation.data.severity.toUpperCase()] || 'bg-gray-600'}`}>
                      {cvePocMutation.data.severity.toUpperCase()}
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
                  {[
                    ['CVSS', cvePocMutation.data.cvss_score],
                    ['EPSS', cvePocMutation.data.epss_score],
                    ['KEV', cvePocMutation.data.kev],
                    ['Published', cvePocMutation.data.publication_date],
                  ].map(([label, value]) => (
                    <div key={label} className="bg-gray-800/60 rounded-lg px-3 py-2">
                      <div className="text-[10px] text-gray-500">{label}</div>
                      <div className="text-sm text-gray-200 font-medium truncate">{value || 'N/A'}</div>
                    </div>
                  ))}
                </div>

                {(cvePocMutation.data.vendor || (cvePocMutation.data.cwe?.length ?? 0) > 0) && (
                  <div className="flex items-center gap-2 flex-wrap mt-3">
                    {cvePocMutation.data.vendor && (
                      <span className="text-[10px] px-2 py-1 rounded bg-gray-800 border border-gray-700 text-gray-300">
                        {cvePocMutation.data.vendor} {cvePocMutation.data.affected_product}
                      </span>
                    )}
                    {cvePocMutation.data.cwe?.map((c) => (
                      <span key={c} className="text-[10px] px-2 py-1 rounded bg-gray-800 border border-gray-700 font-mono text-cyan-400">{c}</span>
                    ))}
                  </div>
                )}

                {cvePocMutation.data.kev === 'Yes' && (
                  <div className="mt-3 flex items-start gap-2 bg-red-900/20 border border-red-800/40 rounded-lg px-3 py-2">
                    <ShieldCheck className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                    <div>
                      <p className="text-xs font-medium text-red-300">CISA Known Exploited Vulnerability — actively exploited in the wild</p>
                      {cvePocMutation.data.kev_notes && <p className="text-[10px] text-red-400/80 mt-0.5">{cvePocMutation.data.kev_notes}</p>}
                    </div>
                  </div>
                )}
              </Card>

              {cvePocMutation.data.sources?.github?.pocs && cvePocMutation.data.sources.github.pocs.length > 0 && (
                <Card>
                  <div className="flex items-center gap-2 mb-3">
                    <Star className="w-4 h-4 text-yellow-400" />
                    <h3 className="text-sm font-semibold text-gray-300">
                      GitHub PoCs
                      <span className="ml-2 text-[10px] font-mono text-gray-500">{cvePocMutation.data.sources.github.count} found</span>
                    </h3>
                  </div>
                  <div className="space-y-2">
                    {cvePocMutation.data.sources.github.pocs.map((poc, i) => (
                      <div key={i} className="bg-gray-950/50 border border-gray-800 rounded-lg px-3 py-2 flex items-center gap-2 flex-wrap">
                        <div className="flex-1 min-w-0">
                          <div className="text-xs font-mono text-gray-300 truncate">{poc.name || poc.html_url}</div>
                          {poc.description && <div className="text-[10px] text-gray-500 truncate">{poc.description}</div>}
                        </div>
                        {typeof poc.stargazers === 'number' && (
                          <span className="text-[10px] text-gray-400 flex items-center gap-1"><Star className="w-3 h-3 text-yellow-500" />{poc.stargazers}</span>
                        )}
                        {poc.html_url && (
                          <a href={poc.html_url} target="_blank" rel="noopener noreferrer" className="text-webforge-400 hover:text-webforge-300">
                            <ExternalLink className="w-4 h-4" />
                          </a>
                        )}
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {cvePocMutation.data.sources?.metasploit_exploitdb_nuclei && (
                <Card>
                  <h3 className="text-sm font-semibold text-gray-300 mb-3">Ready-to-Run Exploits</h3>
                  <div className="space-y-2">
                    {(() => {
                      const tools = cvePocMutation.data.sources!.metasploit_exploitdb_nuclei!
                      return [
                        tools.metasploit && { name: 'Metasploit', cmd: tools.metasploit.command, extra: tools.metasploit.rank },
                        tools.exploitdb && { name: 'ExploitDB', cmd: tools.exploitdb.command, extra: undefined },
                        tools.nuclei && { name: 'Nuclei', cmd: tools.nuclei.command, extra: undefined },
                      ].filter((x): x is { name: string; cmd: string; extra: string | undefined } => Boolean(x)).map((t, i) => (
                        <div key={i} className="flex items-start gap-3 bg-gray-950/50 border border-gray-800 rounded-lg px-3 py-2">
                          <span className="text-[10px] px-2 py-0.5 rounded bg-webforge-600/20 text-webforge-400 font-bold shrink-0 mt-1">{t.name}</span>
                          <div className="min-w-0">
                            <code className="text-xs font-mono text-green-400 whitespace-pre-wrap break-words">{t.cmd}</code>
                            {t.extra && <div className="text-[10px] text-gray-500 mt-0.5">Rank: {t.extra}</div>}
                          </div>
                        </div>
                      ))
                    })()}
                  </div>
                </Card>
              )}

              {cvePocMutation.data.sources?.bug_bounty && (
                <Card>
                  <h3 className="text-sm font-semibold text-gray-300 mb-3">Bug Bounty Reports</h3>
                  <div className="space-y-2">
                    {cvePocMutation.data.sources.bug_bounty.map((r, i) => (
                      <div key={i} className="flex items-center gap-2 flex-wrap">
                        <span className="text-[10px] px-2 py-0.5 rounded bg-gray-800 border border-gray-700 text-gray-300">{r.source}</span>
                        <span className="text-[10px] text-gray-500">PoC: {r.poc_available || 'N/A'}</span>
                        <a href={r.url} target="_blank" rel="noopener noreferrer" className="text-webforge-400 hover:text-webforge-300 text-xs inline-flex items-center gap-1">
                          Open report <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {cvePocMutation.data.sources?.labs && (
                <Card>
                  <h3 className="text-sm font-semibold text-gray-300 mb-3">Practice Labs</h3>
                  <div className="space-y-2">
                    {cvePocMutation.data.sources.labs.htb && (
                      <a href={cvePocMutation.data.sources.labs.htb} target="_blank" rel="noopener noreferrer" className="text-xs text-webforge-400 hover:text-webforge-300 inline-flex items-center gap-1">
                        HackTheBox machine <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                    {cvePocMutation.data.sources.labs.thm && (
                      <a href={cvePocMutation.data.sources.labs.thm} target="_blank" rel="noopener noreferrer" className="text-xs text-webforge-400 hover:text-webforge-300 inline-flex items-center gap-1">
                        TryHackMe room <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                    {cvePocMutation.data.sources.labs.docker_vulhub && (
                      <pre className="text-xs text-gray-400 font-mono whitespace-pre-wrap break-words bg-gray-950/50 border border-gray-800 rounded-lg p-3 mt-1">{cvePocMutation.data.sources.labs.docker_vulhub}</pre>
                    )}
                  </div>
                </Card>
              )}

              {cvePocMutation.data.remediation && (
                <Card>
                  <div className="flex items-center gap-1.5 text-[10px] text-cyan-400 font-medium mb-1.5">
                    <CheckCircle className="w-3 h-3" /> Remediation
                  </div>
                  <p className="text-xs text-gray-400">{cvePocMutation.data.remediation}</p>
                </Card>
              )}

              {cvePocMutation.data.errors && cvePocMutation.data.errors.length > 0 && (
                <Card>
                  <h3 className="text-sm font-semibold text-gray-300 mb-2">Partial Lookup Warnings</h3>
                  <ul className="space-y-1">
                    {cvePocMutation.data.errors.map((err, i) => (
                      <li key={i} className="text-[10px] font-mono text-gray-500">{err}</li>
                    ))}
                  </ul>
                </Card>
              )}
            </div>
          )}
        </div>
      )}

      {/* Tab: Exploit PoC */}
      {tab === 'exploit' && (
        <div className="space-y-4">
          <Card>
            <h3 className="text-sm font-semibold text-gray-300 mb-3">Generate & Run Exploit</h3>
            <p className="text-xs text-gray-500 mb-4">Select a vulnerability type and target URL to generate a PoC and optionally run it.</p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Vulnerability Type</label>
                <select value={exploitVuln} onChange={(e) => setExploitVuln(e.target.value)} className="w-full bg-gray-800/80 border border-gray-700/60 rounded-lg px-4 py-2.5 text-white focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20 outline-none transition-colors text-sm">
                  <option value="">Select vulnerability...</option>
                  <option value="sql_injection">SQL Injection</option>
                  <option value="xss">Cross-Site Scripting (XSS)</option>
                  <option value="lfi">Local File Inclusion (LFI)</option>
                  <option value="rfi">Remote File Inclusion (RFI)</option>
                  <option value="ssti">Server-Side Template Injection (SSTI)</option>
                  <option value="ssrf">Server-Side Request Forgery (SSRF)</option>
                  <option value="command_injection">Command Injection</option>
                  <option value="xxe">XML External Entity (XXE)</option>
                  <option value="open_redirect">Open Redirect</option>
                  <option value="weak_password">Weak Password / Brute Force</option>
                  <option value="information_disclosure">Information Disclosure</option>
                </select>
              </div>
              <Input label="Target URL" value={exploitTarget} onChange={(e) => setExploitTarget(e.target.value)} placeholder="https://target.com" />
              <Input label="Details (optional)" value={exploitDetails} onChange={(e) => setExploitDetails(e.target.value)} placeholder="e.g. vulnerable parameter: id" />
            </div>
            <Button
              onClick={() => exploitMutation.mutate()}
              disabled={!exploitVuln || !exploitTarget || exploitMutation.isPending}
              loading={exploitMutation.isPending}
              className="mt-4"
              color="webforge"
            >
              <Zap className="w-4 h-4 mr-1" /> Generate & Run PoC
            </Button>
          </Card>

          {exploitMutation.isError && (
            <Card className="border-red-800">
              <div className="text-sm text-red-400">{getErrorMessage(exploitMutation.error)}</div>
            </Card>
          )}

          {exploitMutation.isPending && <Spinner text="Generating PoC and running exploit..." color="webforge" />}

          {exploitMutation.data && (
            <Card>
              <h3 className="text-sm font-semibold text-gray-300 mb-3">Exploit Result</h3>
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  {exploitMutation.data.success ? (
                    <CheckCircle className="w-5 h-5 text-green-400" />
                  ) : (
                    <AlertTriangle className="w-5 h-5 text-yellow-400" />
                  )}
                  <span className={`text-sm font-medium ${exploitMutation.data.success ? 'text-green-400' : 'text-yellow-400'}`}>
                    {exploitMutation.data.success ? 'Module executed' : 'PoC generated (no matching module)'}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="bg-gray-800/60 rounded-lg px-3 py-2">
                    <div className="text-[10px] text-gray-500">Vulnerability</div>
                    <div className="text-sm text-gray-200 capitalize">{exploitMutation.data.vulnerability.replace(/_/g, ' ')}</div>
                  </div>
                  <div className="bg-gray-800/60 rounded-lg px-3 py-2">
                    <div className="text-[10px] text-gray-500">Module</div>
                    <div className="text-sm font-mono text-webforge-400">{exploitMutation.data.module_used}</div>
                  </div>
                  <div className="bg-gray-800/60 rounded-lg px-3 py-2">
                    <div className="text-[10px] text-gray-500">Target</div>
                    <div className="text-sm font-mono text-gray-300 truncate">{exploitMutation.data.target}</div>
                  </div>
                </div>

                {exploitMutation.data.poc_generated && (
                  <div className="bg-gray-950/50 border border-gray-800 rounded-lg p-3">
                    <div className="flex items-center gap-1.5 text-[10px] text-webforge-400 font-medium mb-1.5">
                      <Zap className="w-3 h-3" /> Generated PoC
                    </div>
                    <pre className="text-xs text-green-400 font-mono whitespace-pre-wrap break-words">{exploitMutation.data.poc_generated}</pre>
                  </div>
                )}

                {exploitMutation.data.remediation && (
                  <div className="bg-gray-950/50 border border-gray-800 rounded-lg p-3">
                    <div className="flex items-center gap-1.5 text-[10px] text-cyan-400 font-medium mb-1.5">
                      <CheckCircle className="w-3 h-3" /> Remediation
                    </div>
                    <p className="text-xs text-gray-400">{exploitMutation.data.remediation}</p>
                  </div>
                )}

                {exploitMutation.data.execution_result && (
                  <div className="bg-gray-950/50 border border-gray-800 rounded-lg p-3">
                    <div className="flex items-center gap-1.5 text-[10px] text-purple-400 font-medium mb-1.5">
                      <TerminalIcon className="w-3 h-3" /> Execution Result
                    </div>
                    <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap break-words">{JSON.stringify(exploitMutation.data.execution_result, null, 2)}</pre>
                  </div>
                )}
              </div>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}

function TerminalIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="4 17 10 11 4 5" />
      <line x1="12" y1="19" x2="20" y2="19" />
    </svg>
  )
}
