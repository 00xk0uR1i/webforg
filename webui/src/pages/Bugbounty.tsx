import { useEffect, useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Crosshair, Play, StopCircle, Search, FileText, FolderOpen, Shield, Bug, Database, Globe, Layers, Terminal, RefreshCw, AlertTriangle, CheckCircle2 } from 'lucide-react'
import api from '../api'
import { PageHeader, Card, Button, Spinner, Input, Stats, Table } from '../components/UI'
import { severityLower } from '../utils/colors'
import type {
  BbActionItem,
  BbActionsResponse,
  BbJobView,
  BbTargetInfo,
  BbCveHit,
  BbCveSearchHit,
  BbStatusData,
  BbTargetsResponse,
  BbTargetFilesResponse,
  BbJobLog,
  BbRunResponse,
  BbRunExploitResponse,
  BbStopResponse,
  BbReportResponse,
  BbReportViewResponse,
} from '../types'

const TABS = [
  { value: 'overview', label: 'Overview', icon: Globe },
  { value: 'targets', label: 'Targets', icon: FolderOpen },
  { value: 'cve', label: 'CVE', icon: Shield },
  { value: 'reports', label: 'Reports', icon: FileText },
]

export default function Bugbounty() {
  const qc = useQueryClient()
  const [tab, setTab] = useState('overview')
  const [action, setAction] = useState('recon')
  const [runTarget, setRunTarget] = useState('')
  const [args, setArgs] = useState('')
  const [hosts, setHosts] = useState('')
  const [selectedTarget, setSelectedTarget] = useState<string | null>(null)
  const [cveQuery, setCveQuery] = useState('')
  const [exploitCve, setExploitCve] = useState('')
  const [exploitTarget, setExploitTarget] = useState('')
  const [exploitSev, setExploitSev] = useState('')
  const [reportTarget, setReportTarget] = useState('')
  const [includeAll, setIncludeAll] = useState(false)
  const [viewReport, setViewReport] = useState<string | null>(null)
  const termRef = useRef<HTMLPreElement>(null)

  const { data: status } = useQuery<BbStatusData>({ queryKey: ['bb', 'status'], queryFn: async () => (await api.get<BbStatusData>('/bb/status')).data, refetchInterval: 5000 })
  const { data: actions } = useQuery<BbActionsResponse>({ queryKey: ['bb', 'actions'], queryFn: async () => (await api.get<BbActionsResponse>('/bb/actions')).data })
  const { data: targets } = useQuery<BbTargetInfo[]>({ queryKey: ['bb', 'targets'], queryFn: async () => (await api.get<BbTargetsResponse>('/bb/targets')).data.targets, refetchInterval: 5000 })
  const { data: jobs } = useQuery<BbJobView[]>({ queryKey: ['bb', 'jobs'], queryFn: async () => (await api.get<BbJobView[]>('/bb/jobs')).data, refetchInterval: 2000 })
  const { data: foundCves } = useQuery<BbCveHit[]>({ queryKey: ['bb', 'vuln-cves'], queryFn: async () => (await api.get<BbCveHit[]>('/bb/vuln/cves')).data })

  const active = jobs?.find((j) => !j.done) ?? null
  const lastJobIdRef = useRef<number | null>(null)
  useEffect(() => {
    if (active?.id) lastJobIdRef.current = active.id
  }, [active?.id])
  const { data: jobLog } = useQuery<BbJobLog>({
    queryKey: ['bb', 'log', active?.id],
    queryFn: async () => (await api.get<BbJobLog>(`/bb/job/${active!.id}/log`)).data,
    refetchInterval: active ? 1500 : false,
    enabled: !!active,
  })
  const [lastLog, setLastLog] = useState<BbJobLog | null>(null)
  useEffect(() => {
    if (jobLog?.lines) setLastLog(jobLog)
  }, [jobLog])
  useEffect(() => {
    if (!active && lastJobIdRef.current && lastLog && !lastLog.done) {
      api.get<BbJobLog>(`/bb/job/${lastJobIdRef.current}/log`).then((r) => {
        if (r.data?.lines) setLastLog(r.data)
      }).catch(() => {})
    }
  }, [active, lastLog?.done])
  const terminalLines = (jobLog?.lines || lastLog?.lines || []) as string[]

  const { data: cveResults } = useQuery<BbCveSearchHit[]>({
    queryKey: ['bb', 'cve-search', cveQuery.trim()],
    queryFn: async () => (await api.get<BbCveSearchHit[]>('/bb/cve/search', { params: { q: cveQuery.trim(), limit: 30 } })).data,
    enabled: cveQuery.trim().length >= 3,
  })

  const { data: targetFiles } = useQuery<BbTargetFilesResponse>({
    queryKey: ['bb', 'target-files', selectedTarget],
    queryFn: async () => (await api.get<BbTargetFilesResponse>(`/bb/target/${encodeURIComponent(selectedTarget!)}`)).data,
    enabled: !!selectedTarget,
  })

  const { data: reportView } = useQuery<BbReportViewResponse>({
    queryKey: ['bb', 'report-view', viewReport],
    queryFn: async () => (await api.get<BbReportViewResponse>(`/bb/report/view/${encodeURIComponent(viewReport!)}`)).data,
    enabled: !!viewReport,
  })

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['bb', 'jobs'] })
    qc.invalidateQueries({ queryKey: ['bb', 'status'] })
    qc.invalidateQueries({ queryKey: ['bb', 'targets'] })
  }

  const runMut = useMutation({
    mutationFn: async (body: { action: string; target: string; args: string; hosts: string }) => (await api.post<BbRunResponse>('/bb/run', body)).data,
    onSuccess: () => invalidate(),
  })

  const exploitMut = useMutation({
    mutationFn: async (body: { cve: string; target: string; severity: string }) => (await api.post<BbRunExploitResponse>('/bb/run-exploit', body)).data,
    onSuccess: () => invalidate(),
  })

  const stopMut = useMutation({
    mutationFn: async () => (await api.post<BbStopResponse>('/bb/stop')).data,
    onSuccess: () => invalidate(),
  })

  const reportMut = useMutation({
    mutationFn: async (body: { target: string; include_all: boolean }) => (await api.post<BbReportResponse>('/bb/report/generate', body)).data,
    onSuccess: () => {
      invalidate()
      qc.invalidateQueries({ queryKey: ['bb', 'report-view'] })
    },
  })

  useEffect(() => {
    if (termRef.current && terminalLines.length) {
      termRef.current.scrollTop = termRef.current.scrollHeight
    }
  }, [terminalLines.length, active?.id])

  const actionList = actions?.actions
  const needsHosts = ['xss', 'scan', 'crlf', 'takeover', 'redirect', 'cors', 'ssrf'].includes(action)

  const runBody = (target: string) => ({
    action,
    target,
    args,
    hosts: needsHosts ? hosts : '',
  })

  const submit = () => {
    if (!runTarget.trim()) return
    runMut.mutate(runBody(runTarget.trim()))
  }

  const submitExploit = () => {
    if (!exploitCve.trim() || !exploitTarget.trim()) return
    exploitMut.mutate({ cve: exploitCve.trim(), target: exploitTarget.trim(), severity: exploitSev })
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader
        title="Bug Bounty Workspace"
        subtitle="Run the recon -> scan -> exploit workflow against program targets with live streaming output"
        icon={<Crosshair className="w-8 h-8" />}
        color="webforge"
      >
        <div className="flex items-start gap-2 px-1">
          <Bug className="w-4 h-4 text-webforge-400 shrink-0 mt-0.5" />
          <p className="text-xs text-gray-500">Workspace: <span className="font-mono text-gray-400">{status?.workspace || '…'}</span> — one job runs at a time; logs stream live.</p>
        </div>
      </PageHeader>

      <div className="flex flex-wrap gap-2">
        {TABS.map((t) => {
          const Icon = t.icon
          return (
            <button
              key={t.value}
              onClick={() => setTab(t.value)}
              className={`flex items-center gap-2 text-xs px-3 py-2 rounded-lg border transition-colors min-h-[36px] ${
                tab === t.value ? 'bg-webforge-600/15 border-webforge-500/40 text-webforge-400' : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'
              }`}
            >
              <Icon className="w-4 h-4" />
              {t.label}
            </button>
          )
        })}
      </div>

      {/* Global job terminal */}
      <Card className={active ? 'border-webforge-500/40' : ''}>
        <div className="flex items-center gap-2 mb-2">
          <Terminal className={`w-4 h-4 ${active ? 'text-webforge-400' : 'text-gray-500'}`} />
          <div className="text-[11px] font-bold uppercase tracking-widest text-gray-500">Job Output</div>
          {active && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-500/15 text-green-400 font-bold">RUNNING</span>
          )}
          <span className="ml-auto text-[11px] text-gray-600 font-mono truncate">{active ? active.cmd : 'idle'}</span>
          {active && (
            <Button color="red" onClick={() => stopMut.mutate()} loading={stopMut.isPending} className="!px-3 !py-1.5 !min-h-[32px] !text-xs">
              <StopCircle className="w-4 h-4 mr-1" /> Stop
            </Button>
          )}
        </div>
        <pre
          ref={termRef}
          className="bg-gray-950/80 border border-gray-800 rounded-lg p-3 text-[11px] text-gray-300 font-mono whitespace-pre-wrap break-all max-h-64 overflow-y-auto"
        >
          {terminalLines.length ? (
            <div>
              {!active && lastLog && <div className="mb-1.5 text-[10px] text-gray-600 font-mono">exit code: {lastLog.code ?? '?'} — last job finished</div>}
              {terminalLines.join('\n')}
            </div>
          ) : (
            'No job running yet. Start an action from the Targets or Run panel below.'
          )}
        </pre>
      </Card>

      {tab === 'overview' && (
        <>
          <Stats
            stats={[
              { label: 'Targets', value: status?.targets ?? 0, color: 'webforge', icon: <FolderOpen className="w-4 h-4" /> },
              { label: 'Scan Files', value: status?.scans ?? 0, color: 'amber', icon: <Layers className="w-4 h-4" /> },
              { label: 'CVE Templates', value: status?.cve ?? 0, color: 'red', icon: <Shield className="w-4 h-4" /> },
              { label: 'Wordlists', value: status?.wordlists ?? 0, color: 'cyan', icon: <Database className="w-4 h-4" /> },
              { label: 'Loot Files', value: status?.loot ?? 0, color: 'purple', icon: <Bug className="w-4 h-4" /> },
            ]}
          />

          <Card>
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              <div className="text-[11px] font-bold uppercase tracking-widest text-gray-500">Recent CVEs found by scans</div>
            </div>
            {!foundCves || foundCves.length === 0 ? (
              <div className="text-xs text-gray-600">No CVE hits recorded yet — run a wapiti (<span className="font-mono">vuln</span>) or nuclei (<span className="font-mono">scan</span>) job to populate.</div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
                {foundCves.slice(0, 10).map((c) => (
                  <div key={c.cve} className="flex items-start gap-2 text-xs bg-gray-950/50 border border-gray-800 rounded-lg p-2.5">
                    <Shield className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                    <div className="min-w-0">
                      <div className="font-mono text-red-400">{c.cve}</div>
                      <div className="text-gray-500 truncate mt-0.5">{c.info || c.target || c.file}</div>
                      <div className="text-gray-600 text-[10px] mt-0.5">{c.target} · {c.vtype}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </>
      )}

      {tab === 'targets' && (
        <>
          <Card>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
              <Input label="Target (domain or URL)" value={runTarget} onChange={(e) => setRunTarget(e.target.value)} placeholder="example.com" />
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Action</label>
                <select
                  value={action}
                  onChange={(e) => setAction(e.target.value)}
                  className="w-full bg-gray-800/80 border border-gray-700/60 rounded-lg px-3 py-3 text-white text-sm focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20 outline-none transition-colors"
                >
                  {actionList?.map((a) => (
                    <option key={a.value} value={a.value}>{a.label}</option>
                  ))}
                </select>
              </div>
              {needsHosts && (
                <Input label="Hosts file (optional)" value={hosts} onChange={(e) => setHosts(e.target.value)} placeholder="recon/example.com/httpx.txt" />
              )}
              <Input label="Extra args" value={args} onChange={(e) => setArgs(e.target.value)} placeholder="--threads 10" />
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Button color="green" onClick={submit} loading={runMut.isPending} disabled={!runTarget.trim()}>
                <Play className="w-4 h-4 mr-2" /> Run {actionList?.find((a) => a.value === action)?.label.split(' ')[0] || action}
              </Button>
              <span className="text-[11px] text-gray-600">{actionList?.find((a) => a.value === action)?.label}</span>
            </div>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="space-y-2">
              <div className="text-[11px] font-bold uppercase tracking-widest text-gray-500">Recon Targets</div>
              {(targets || []).length === 0 ? (
                <Card className="text-center py-8">
                  <FolderOpen className="w-8 h-8 mx-auto mb-2 text-gray-700" />
                  <div className="text-sm text-gray-400">No targets yet</div>
                  <div className="text-xs text-gray-600 mt-1">Add one above — running any action registers the target.</div>
                </Card>
              ) : (
                (targets || []).map((t) => (
                  <Card key={t.name} className={selectedTarget === t.name ? 'border-webforge-500/50' : ''}>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setSelectedTarget(selectedTarget === t.name ? null : t.name)}
                        className="text-sm font-medium text-webforge-400 hover:text-webforge-300 font-mono truncate"
                      >
                        {t.name}
                      </button>
                      {t.report && <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-500/15 text-green-400 font-bold flex items-center gap-1"><FileText className="w-3 h-3" />report</span>}
                      <span className="ml-auto text-[11px] text-gray-600">{t.files.length} file{t.files.length === 1 ? '' : 's'}</span>
                    </div>
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {(['recon', 'urls', 'scan', 'vuln', 'xss', 'crawl'] as const).map((act) => (
                        <button
                          key={act}
                          onClick={() => {
                            setAction(act)
                            runMut.mutate({ action: act, target: t.name, args: '', hosts: '' })
                          }}
                          disabled={!!active}
                          className="text-[11px] px-2 py-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 border border-gray-700 disabled:opacity-40 min-h-[28px]"
                        >
                          {act}
                        </button>
                      ))}
                    </div>
                  </Card>
                ))
              )}
            </div>

            <div>
              <div className="text-[11px] font-bold uppercase tracking-widest text-gray-500 mb-2">
                {selectedTarget ? `Recon files — ${selectedTarget}` : 'Recon files'}
              </div>
              {!selectedTarget ? (
                <Card className="text-center py-8">
                  <Search className="w-8 h-8 mx-auto mb-2 text-gray-700" />
                  <div className="text-sm text-gray-400">Select a target to inspect its recon files</div>
                </Card>
              ) : !targetFiles ? (
                <Card><Spinner text="Loading files..." color="webforge" /></Card>
              ) : (
                <div className="space-y-2">
                  {targetFiles.files.length === 0 && (
                    <Card className="text-center py-8">
                      <div className="text-sm text-gray-400">No recon files yet</div>
                      <div className="text-xs text-gray-600 mt-1">Run a <span className="font-mono">recon</span> job to start populating.</div>
                    </Card>
                  )}
                  {targetFiles.files.map((f) => (
                    <details key={f.name} className="bg-gray-900/40 border border-gray-800/40 rounded-xl">
                      <summary className="cursor-pointer px-3 py-2 text-xs font-mono text-gray-300 hover:text-webforge-400 list-none flex items-center gap-2">
                        <FileText className="w-3.5 h-3.5 text-gray-600" />
                        {f.name}
                        <span className="ml-auto text-gray-600 text-[10px]">{f.lines.length} lines</span>
                      </summary>
                      <pre className="bg-gray-950/60 p-3 text-[11px] text-gray-400 font-mono whitespace-pre-wrap break-all max-h-72 overflow-y-auto border-t border-gray-800/50">
                        {f.lines.join('\n') || '(empty)'}
                      </pre>
                    </details>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {tab === 'cve' && (
        <>
          <Card>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <Input label="Exploit CVE" value={exploitCve} onChange={(e) => setExploitCve(e.target.value)} placeholder="CVE-2023-25157" />
              <Input label="Target URL" value={exploitTarget} onChange={(e) => setExploitTarget(e.target.value)} placeholder="https://target.com" />
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Severity (optional)</label>
                <select
                  value={exploitSev}
                  onChange={(e) => setExploitSev(e.target.value)}
                  className="w-full bg-gray-800/80 border border-gray-700/60 rounded-lg px-3 py-3 text-white text-sm focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20 outline-none transition-colors"
                >
                  <option value="">any</option>
                  {actions?.severities?.map((s: string) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>
            </div>
            <div className="mt-3">
              <Button color="red" onClick={submitExploit} loading={exploitMut.isPending} disabled={!exploitCve.trim() || !exploitTarget.trim()}>
                <Bug className="w-4 h-4 mr-2" /> Exploit {exploitCve.trim() || 'CVE'} against target
              </Button>
            </div>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Table
              title={`CVEs found by scans (${foundCves?.length ?? 0})`}
              color="red"
              columns={['CVE', 'Target', 'Source']}
              rows={(foundCves || []).map((c) => [
                <span key="c" className="font-mono text-red-400">{c.cve}</span>,
                c.target || '-',
                <span key="f" className="text-gray-500 text-[11px]">{c.file}</span>,
              ])}
            />

            <Card>
              <div className="flex items-center gap-2 mb-3">
                <Search className="w-4 h-4 text-webforge-400" />
                <div className="text-[11px] font-bold uppercase tracking-widest text-gray-500">Search CVE templates</div>
              </div>
              <Input value={cveQuery} onChange={(e) => setCveQuery(e.target.value)} placeholder="CVE-2023 (min 3 chars)" />
              <div className="mt-3 space-y-1.5 max-h-80 overflow-y-auto">
                {cveQuery.trim().length < 3 ? (
                  <div className="text-xs text-gray-600">Type at least 3 characters to search the {status?.cve ?? '…'} local templates.</div>
                ) : cveResults === undefined ? (
                  <Spinner text="Searching..." color="webforge" />
                ) : cveResults.length === 0 ? (
                  <div className="text-xs text-gray-600">No matching templates.</div>
                ) : (
                  cveResults.map((r) => (
                    <button
                      key={r.id}
                      onClick={() => { setExploitCve(r.id); setTab('cve') }}
                      className="w-full flex items-center gap-2 text-left text-xs bg-gray-950/50 border border-gray-800 rounded-lg px-2.5 py-2 hover:border-webforge-500/50"
                    >
                      <span className="font-mono text-webforge-400 flex-1 truncate">{r.id}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${severityLower[r.severity] || severityLower.unknown}`}>{r.severity}</span>
                    </button>
                  ))
                )}
              </div>
            </Card>
          </div>
        </>
      )}

      {tab === 'reports' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Card>
            <div className="flex items-center gap-2 mb-3">
              <FileText className="w-4 h-4 text-webforge-400" />
              <div className="text-[11px] font-bold uppercase tracking-widest text-gray-500">Generate report</div>
            </div>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Target</label>
                <select
                  value={reportTarget}
                  onChange={(e) => setReportTarget(e.target.value)}
                  className="w-full bg-gray-800/80 border border-gray-700/60 rounded-lg px-3 py-3 text-white text-sm focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20 outline-none transition-colors"
                >
                  <option value="">Select target…</option>
                  {(targets || []).map((t) => (
                    <option key={t.name} value={t.name}>{t.name}</option>
                  ))}
                </select>
              </div>
              <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer">
                <input type="checkbox" checked={includeAll} onChange={(e) => setIncludeAll(e.target.checked)} className="accent-webforge-500" />
                Include empty asset files
              </label>
              <Button color="green" onClick={() => reportMut.mutate({ target: reportTarget, include_all: includeAll })} loading={reportMut.isPending} disabled={!reportTarget}>
                <RefreshCw className="w-4 h-4 mr-2" /> Generate report.md
              </Button>
              {reportMut.data && (
                <div className="text-[11px] text-green-400 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4" /> Saved to {reportMut.data.file} — {reportMut.data.findings} findings
                </div>
              )}
            </div>
          </Card>

          <Card>
            <div className="flex items-center gap-2 mb-3">
              <FileText className="w-4 h-4 text-gray-500" />
              <div className="text-[11px] font-bold uppercase tracking-widest text-gray-500">View existing report</div>
            </div>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Target with report.md</label>
                <select
                  value={viewReport || ''}
                  onChange={(e) => setViewReport(e.target.value || null)}
                  className="w-full bg-gray-800/80 border border-gray-700/60 rounded-lg px-3 py-3 text-white text-sm focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20 outline-none transition-colors"
                >
                  <option value="">Select target…</option>
                  {(targets || []).filter((t) => t.report).map((t) => (
                    <option key={t.name} value={t.name}>{t.name}</option>
                  ))}
                </select>
              </div>
              {reportView && (
                <pre className="bg-gray-950/60 border border-gray-800 rounded-lg p-3 text-[11px] text-gray-300 font-mono whitespace-pre-wrap break-all max-h-[480px] overflow-y-auto">
                  {reportView.markdown}
                </pre>
              )}
            </div>
          </Card>
        </div>
      )}
    </div>
  )
}
