import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, useRef } from 'react'
import { Terminal, XCircle, Wifi, WifiOff, Radio, Plus, Trash2, Upload, Download, KeyRound, Cpu, Shield } from 'lucide-react'
import clsx from 'clsx'
import api from '../api'
import { PageHeader, Card, Input, Button, Stats, Spinner, EmptyState, SectionHeader, OutputBlock } from '../components/UI'
import { ConfirmDialog } from '../components/ConfirmDialog'
import type {
  SessionInfo,
  SessionListResponse,
  ListenerInfo,
  ListenerListResponse,
  ListenerStartResponse,
  ListenerAgent,
  SendResponse,
  SessionProbeResponse,
  SessionUpgradeResponse,
  SessionDownloadResponse,
  SessionUploadResponse,
  SessionHashdumpResponse,
  SessionSysinfoResponse,
  CveFinding,
  SessionCveScanResponse,
  SessionCveExploitResponse,
} from '../types'

const EXPLOITABLE = ['CVE-2022-0492', 'CVE-2024-21626', 'CVE-2019-5736', 'CTR-PRIV', 'CTR-DOCKERSOCK', 'CTR-PIDLEAK']

export default function Sessions() {
  const queryClient = useQueryClient()
  const [activeId, setActiveId] = useState<string | null>(null)
  const [cmdInput, setCmdInput] = useState('')
  const [cmdHistory, setCmdHistory] = useState<Array<{ cmd: string; output: string }>>([])
  const [showListenerForm, setShowListenerForm] = useState(false)
  const [listenerHost, setListenerHost] = useState('0.0.0.0')
  const [listenerPort, setListenerPort] = useState('4444')
  const [listenerPayload, setListenerPayload] = useState('shell')
  const [listenerTls, setListenerTls] = useState(false)
  const [agentInfo, setAgentInfo] = useState<ListenerAgent | null>(null)
  const [confirmKill, setConfirmKill] = useState<string | null>(null)
  const [confirmStopListener, setConfirmStopListener] = useState<string | null>(null)
  const [dlPath, setDlPath] = useState('')
  const [upPath, setUpPath] = useState('')
  const upFileRef = useRef<HTMLInputElement>(null)
  const [postExTab, setPostExTab] = useState<'download' | 'upload' | 'hashdump' | 'sysinfo' | 'cvescan'>('download')
  const [postExResult, setPostExResult] = useState<Array<{ title: string; body: string }>>([])
  const [cveFindings, setCveFindings] = useState<CveFinding[] | null>(null)
  const [cveScanSummary, setCveScanSummary] = useState('')
  const [cveExploitTarget, setCveExploitTarget] = useState('')
  const [cveExploiting, setCveExploiting] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['sessions'],
    queryFn: async () => {
      const res = await api.get<SessionListResponse>('/sessions')
      return res.data.sessions
    },
    refetchInterval: 5000,
  })

  const { data: listenersData } = useQuery({
    queryKey: ['listeners'],
    queryFn: async () => {
      const res = await api.get<ListenerListResponse>('/listeners')
      return res.data.listeners
    },
    refetchInterval: 3000,
  })

  const killMutation = useMutation({
    mutationFn: async (id: string) => { await api.delete(`/sessions/${id}`) },
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['sessions'] }); if (activeId) setActiveId(null) },
  })

  const sendMutation = useMutation({
    mutationFn: async ({ id, command }: { id: string; command: string }) => {
      const res = await api.post<SendResponse>(`/sessions/${id}/send`, { command })
      return res.data
    },
  })

  const probeMutation = useMutation({
    mutationFn: async (id: string) => { const res = await api.post<SessionProbeResponse>(`/sessions/${id}/probe`); return res.data },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sessions'] }),
  })

  const upgradeMutation = useMutation({
    mutationFn: async (id: string) => { const res = await api.post<SessionUpgradeResponse>(`/sessions/${id}/upgrade`); return res.data },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sessions'] }),
  })

  const startListenerMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post<ListenerStartResponse>('/listeners', { lhost: listenerHost, lport: parseInt(listenerPort), payload_type: listenerPayload, tls: listenerTls })
      return res.data
    },
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['listeners'] }); setShowListenerForm(false) },
  })

  const agentMutation = useMutation({
    mutationFn: async (name: string) => { const res = await api.get<ListenerAgent>(`/listeners/${name}/agent`); return res.data },
  })

  const downloadAgent = (name: string) => {
    agentMutation.mutate(name, {
      onSuccess: (data) => {
        const blob = new Blob([data.agent], { type: 'text/x-python' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `kubesploit-agent-${data.lhost}-${data.lport}.py`
        document.body.appendChild(a)
        a.click()
        a.remove()
        URL.revokeObjectURL(url)
        setAgentInfo(data)
      },
    })
  }

  const stopListenerMutation = useMutation({
    mutationFn: async (name: string) => { await api.delete(`/listeners/${name}`) },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['listeners'] }),
  })

  const downloadMutation = useMutation({
    mutationFn: async ({ id, remote_path }: { id: string; remote_path: string }) => {
      const res = await api.post<SessionDownloadResponse>(`/sessions/${id}/download`, { remote_path })
      return res.data
    },
  })

  const uploadMutation = useMutation({
    mutationFn: async ({ id, remote_path, data_b64 }: { id: string; remote_path: string; data_b64: string }) => {
      const res = await api.post<SessionUploadResponse>(`/sessions/${id}/upload`, { remote_path, data_b64 })
      return res.data
    },
  })

  const hashdumpMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await api.post<SessionHashdumpResponse>(`/sessions/${id}/hashdump`)
      return res.data
    },
  })

  const sysinfoMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await api.post<SessionSysinfoResponse>(`/sessions/${id}/sysinfo`)
      return res.data
    },
  })

  const cveScanMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await api.post<SessionCveScanResponse>(`/sessions/${id}/cve-scan`)
      return res.data
    },
  })

  const cveExploitMutation = useMutation({
    mutationFn: async ({ id, cve }: { id: string; cve: string }) => {
      const res = await api.post<SessionCveExploitResponse>(`/sessions/${id}/cve-exploit`, { cve_id: cve })
      return res.data
    },
  })

  const sessions: SessionInfo[] = data || []
  const listeners: ListenerInfo[] = listenersData || []
  const activeSession = sessions.find((s) => s.id === activeId)

  const handleSend = () => {
    if (!cmdInput.trim() || !activeId) return
    const cmd = cmdInput
    sendMutation.mutate({ id: activeId, command: cmd }, {
      onSuccess: (data) => {
        setCmdHistory((prev) => [...prev, { cmd, output: data.output }])
        setCmdInput('')
        if (!data.alive) queryClient.invalidateQueries({ queryKey: ['sessions'] })
      },
    })
  }

  const handleDownload = () => {
    if (!activeId || !dlPath.trim()) return
    downloadMutation.mutate({ id: activeId, remote_path: dlPath }, {
      onSuccess: (data) => {
        if (data.ok && data.data_b64) {
          const bytes = Uint8Array.from(atob(data.data_b64), (c) => c.charCodeAt(0))
          const blob = new Blob([bytes])
          const url = URL.createObjectURL(blob)
          const a = document.createElement('a')
          a.href = url
          a.download = data.name
          a.click()
          URL.revokeObjectURL(url)
        }
        setPostExResult((prev) => [...prev, { title: `download ${dlPath}`, body: data.ok ? `Saved ${data.name} (${data.size} bytes) — file download started` : 'Download failed' }])
      },
    })
  }

  const handleUpload = () => {
    if (!activeId || !upPath.trim() || !upFileRef.current?.files?.length) return
    const file = upFileRef.current.files[0]
    const reader = new FileReader()
    reader.onload = () => {
      const b64 = (reader.result as string).split(',')[1]
      uploadMutation.mutate({ id: activeId, remote_path: upPath, data_b64: b64 }, {
        onSuccess: (data) => {
          setPostExResult((prev) => [...prev, { title: `upload ${upFileRef.current?.files?.[0]?.name}`, body: data.ok ? `Uploaded ${data.size} bytes to ${data.path}` : 'Upload failed' }])
          setUpPath('')
          if (upFileRef.current) upFileRef.current.value = ''
        },
      })
    }
    reader.readAsDataURL(file)
  }

  const handleHashdump = () => {
    if (!activeId) return
    hashdumpMutation.mutate(activeId, {
      onSuccess: (data) => {
        if (data.ok) {
          setPostExResult((prev) => [...prev, { title: 'hashdump /etc/passwd', body: data.passwd }, { title: 'hashdump /etc/shadow', body: data.shadow }])
        } else {
          setPostExResult((prev) => [...prev, { title: 'hashdump', body: 'Failed — /etc/shadow may not be readable' }])
        }
      },
    })
  }

  const handleSysinfo = () => {
    if (!activeId) return
    sysinfoMutation.mutate(activeId, {
      onSuccess: (data) => {
        setPostExResult((prev) => [...prev, {
          title: `sysinfo ${data.user}@${data.id} (${data.os})`,
          body: [data.uname, data.pwd].join('\n'),
        }])
      },
    })
  }

  const handleCveScan = () => {
    if (!activeId) return
    setCveFindings(null)
    setCveScanSummary('')
    cveScanMutation.mutate(activeId, {
      onSuccess: (data) => {
        setCveFindings(data.findings)
        setCveScanSummary(data.summary)
        const vulnerable = data.findings.filter((f) => f.status === 'vulnerable' || f.status === 'possibly')
        if (vulnerable.length) setCveExploitTarget(vulnerable[0].cve)
        setPostExResult((prev) => [...prev, { title: 'CVE scan', body: data.summary }])
      },
    })
  }

  const handleCveExploit = (cve: string) => {
    if (!activeId || !cve) return
    setCveExploiting(cve)
    cveExploitMutation.mutate({ id: activeId, cve }, {
      onSuccess: (data) => {
        setCveExploiting(null)
        setPostExResult((prev) => [...prev, {
          title: `exploit ${data.cve} — ${data.name}`,
          body: `${data.note}\n\n${data.output}`,
        }])
      },
      onError: () => setCveExploiting(null),
    })
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader title="Sessions" subtitle="Manage active sessions and listeners" icon={<Terminal className="w-8 h-8" />} color="green">
        <Stats stats={[
          { label: 'Active Sessions', value: sessions.filter((s) => s.alive).length, color: 'green' },
          { label: 'Dead Sessions', value: sessions.filter((s) => !s.alive).length, color: sessions.some((s) => !s.alive) ? 'red' : undefined },
          { label: 'Listeners', value: listeners.length, color: 'blue' },
        ]} />
      </PageHeader>

      {/* Listeners */}
      <Card>
        <SectionHeader
          icon={<Radio className="w-4 h-4 text-webforge-400" />}
          title="Listeners"
          action={
            <Button size="sm" color="webforge" className="min-h-[44px] min-w-[44px]" onClick={() => setShowListenerForm(!showListenerForm)}>
              <Plus className="w-3 h-3" /> New
            </Button>
          }
        />
        {showListenerForm && (
          <div className="mt-3 p-3 bg-gray-800/60 rounded-lg border border-gray-700/40">
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-2">
              <Input value={listenerHost} onChange={(e) => setListenerHost(e.target.value)} placeholder="LHOST" className="text-xs font-mono" />
              <Input value={listenerPort} onChange={(e) => setListenerPort(e.target.value)} placeholder="LPORT" className="text-xs font-mono" />
              <select
                value={listenerPayload}
                onChange={(e) => setListenerPayload(e.target.value)}
                className="w-full bg-gray-800/80 border border-gray-700/60 rounded-lg px-3 py-2.5 text-sm text-white focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20 outline-none transition-colors appearance-none"
              >
                <option value="shell">Shell</option>
                <option value="meterpreter">Meterpreter</option>
                <option value="c2">C2 / HTTP/2 agent</option>
              </select>
              <Button onClick={() => startListenerMutation.mutate()} loading={startListenerMutation.isPending} color="green" className="text-sm py-2">Start</Button>
            </div>
            {listenerPayload === 'c2' && (
              <label className="mt-2 flex items-center gap-2 text-xs text-gray-400 cursor-pointer min-h-[36px]">
                <input type="checkbox" checked={listenerTls} onChange={(e) => setListenerTls(e.target.checked)} className="accent-webforge-500" />
                Use HTTP/2 over TLS (self-signed cert generated automatically)
              </label>
            )}
          </div>
        )}
        {listeners.length === 0 ? (
          <EmptyState
            icon={<Radio className="w-8 h-8" />}
            title="No active listeners"
            description="Start a listener to catch incoming reverse connections."
          />
        ) : (
          <div className="space-y-1 mt-3">
            {listeners.map((l) => (
              <div key={l.name} className="flex items-center justify-between gap-2 p-2 hover:bg-gray-800/30 rounded-lg transition-colors">
                <div className="flex items-center gap-3 min-w-0">
                  <span className={clsx('w-2 h-2 rounded-full shrink-0', l.running ? 'bg-green-400' : 'bg-red-400')} />
                  <div className="min-w-0">
                    <span className="font-mono text-xs text-gray-300">{l.name}</span>
                    <span className="text-xs text-gray-500 ml-2">{l.lhost}:{l.lport}</span>
                    <span className="text-xs text-gray-600 ml-2">[{l.payload_type}]</span>
                  </div>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  {l.payload_type.includes('c2') && l.running && (
                    <button onClick={() => downloadAgent(l.name)} className="p-2.5 min-w-[44px] min-h-[44px] text-gray-500 hover:text-cyan-400 transition-colors" title="Download C2 agent payload">
                      <Shield className="w-4 h-4" />
                    </button>
                  )}
                  <button onClick={() => setConfirmStopListener(l.name)} className="p-2.5 min-w-[44px] min-h-[44px] text-gray-500 hover:text-red-400 shrink-0 transition-colors">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {agentInfo && (
        <Card>
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span className="text-[11px] font-bold uppercase tracking-widest text-gray-500">C2 Agent Payload</span>
          </div>
          <p className="text-xs text-gray-500 mb-2">
            Agent saved as <span className="font-mono text-gray-300">kubesploit-agent-{agentInfo.lhost}-{agentInfo.lport}.py</span> — deploy it
            in the target container (requires <span className="font-mono text-cyan-400">h2</span> on the agent) and run with python3.
          </p>
          <OutputBlock>
            {`${agentInfo.tls ? 'https' : 'http'}://${agentInfo.lhost}:${agentInfo.lport}  →  POST /c2/register, /c2/checkin`}
          </OutputBlock>
        </Card>
      )}

      {/* Sessions List */}
      {isLoading ? (
        <Spinner text="Loading sessions..." color="green" />
      ) : sessions.length === 0 ? (
        <EmptyState
          icon={<Terminal className="w-8 h-8" />}
          title="No active sessions"
          description="Run an exploit or wait for a callback."
        />
      ) : (
        <div className="space-y-2">
          {sessions.map((s) => (
            <div
              key={s.id}
              className={clsx(
                'p-3 bg-gray-900/40 border rounded-xl cursor-pointer transition-colors',
                activeId === s.id ? 'border-webforge-600' : 'border-gray-800/40 hover:border-gray-700/50',
              )}
              onClick={() => { setActiveId(s.id); setCmdHistory([]) }}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-3 min-w-0">
                  {s.alive ? <Wifi className="w-4 h-4 text-webforge-400 shrink-0" /> : <WifiOff className="w-4 h-4 text-red-400 shrink-0" />}
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-sm font-medium text-gray-200 truncate">{s.id}</span>
                      <span className={clsx('text-xs px-1.5 py-0.5 rounded', s.alive ? 'bg-webforge-400/10 text-webforge-400' : 'bg-red-400/10 text-red-400')}>{s.alive ? 'alive' : 'dead'}</span>
                      <span className="text-xs px-1.5 py-0.5 rounded bg-gray-800/60 text-gray-400">{s.session_type}</span>
                      {s.platform && <span className="text-xs px-1.5 py-0.5 rounded bg-gray-800/60 text-gray-500">{s.platform}</span>}
                    </div>
                    <div className="text-xs text-gray-500 mt-1 truncate">{s.target} via {s.module_name}</div>
                  </div>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  {s.alive && s.session_type !== 'meterpreter' && (
                    <button onClick={(e) => { e.stopPropagation(); probeMutation.mutate(s.id) }} className="p-2.5 min-w-[44px] min-h-[44px] text-gray-500 hover:text-webforge-400 transition-colors" title="Probe">
                      <Terminal className="w-4 h-4" />
                    </button>
                  )}
                  {s.alive && (
                    <button onClick={(e) => { e.stopPropagation(); upgradeMutation.mutate(s.id) }} className="p-2.5 min-w-[44px] min-h-[44px] text-gray-500 hover:text-yellow-400 transition-colors" title="Upgrade">
                      <Radio className="w-4 h-4" />
                    </button>
                  )}
                  <button onClick={(e) => { e.stopPropagation(); setConfirmKill(s.id) }} className="p-2.5 min-w-[44px] min-h-[44px] text-gray-500 hover:text-red-400 transition-colors" title="Kill">
                    <XCircle className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Terminal */}
      {activeSession && (
        <Card className="p-0 overflow-hidden">
          <div className="px-4 py-2.5 border-b border-gray-800/60 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-webforge-400" />
            <span className="text-sm font-medium truncate">Session {activeSession.id}</span>
            <span className="text-xs text-gray-500 hidden sm:inline">[{activeSession.session_type}] {activeSession.target}</span>
          </div>
          <div className="h-48 sm:h-64 overflow-y-auto p-4 font-mono text-xs space-y-2 bg-gray-950/60">
            {cmdHistory.length === 0 && <div className="text-gray-600">Type a command and press Enter...</div>}
            {cmdHistory.map((entry, i) => (
              <div key={i}>
                <div className="text-webforge-400">$ {entry.cmd}</div>
                <pre className="text-gray-400 whitespace-pre-wrap break-all">{entry.output}</pre>
              </div>
            ))}
          </div>
          <div className="px-4 py-2.5 border-t border-gray-800/60 flex flex-col sm:flex-row gap-2">
            <input
              type="text"
              value={cmdInput}
              onChange={(e) => setCmdInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSend()}
              placeholder="Enter command..."
              className="flex-1 min-w-0 w-full px-3 py-3 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm font-mono text-white placeholder-gray-500 focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20 outline-none transition-colors"
              autoFocus
            />
            <Button onClick={handleSend} disabled={!cmdInput.trim() || sendMutation.isPending} loading={sendMutation.isPending} className="min-h-[44px] py-3 px-4 text-sm">Send</Button>
          </div>
        </Card>
      )}

      {/* Post-Exploitation */}
      {activeSession && (
        <Card>
          <SectionHeader icon={<Cpu className="w-4 h-4 text-webforge-400" />} title="Post-Exploitation" />

          <div className="mt-3 flex gap-1 border-b border-gray-800/60 -mb-px overflow-x-auto">
            {(['download', 'upload', 'hashdump', 'sysinfo', 'cvescan'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setPostExTab(tab)}
                className={clsx(
                  'px-3 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap capitalize',
                  postExTab === tab
                    ? 'border-webforge-500 text-webforge-400'
                    : 'border-transparent text-gray-500 hover:text-gray-300',
                )}
              >
                {tab}
              </button>
            ))}
          </div>

          <div className="pt-4">
            {postExTab === 'download' && (
              <div className="flex flex-col sm:flex-row gap-2">
                <div className="flex-1 min-w-0">
                  <Input value={dlPath} onChange={(e) => setDlPath(e.target.value)} placeholder="Remote path e.g. /etc/shadow" className="text-xs font-mono" onKeyDown={(e) => e.key === 'Enter' && handleDownload()} />
                </div>
                <Button onClick={handleDownload} disabled={!dlPath.trim() || downloadMutation.isPending} loading={downloadMutation.isPending} color="green" className="text-sm py-2 shrink-0">
                  <Download className="w-4 h-4 mr-1" /> Download
                </Button>
              </div>
            )}

            {postExTab === 'upload' && (
              <div className="flex flex-col gap-2">
                <input ref={upFileRef} type="file" className="text-xs text-gray-400 file:mr-3 file:px-3 file:py-1.5 file:rounded-lg file:border-0 file:text-xs file:font-medium file:bg-gray-800/80 file:text-gray-200" />
                <div className="flex flex-col sm:flex-row gap-2">
                  <div className="flex-1 min-w-0">
                    <Input value={upPath} onChange={(e) => setUpPath(e.target.value)} placeholder="Remote path e.g. /tmp/payload" className="text-xs font-mono" onKeyDown={(e) => e.key === 'Enter' && handleUpload()} />
                  </div>
                  <Button onClick={handleUpload} disabled={!upPath.trim() || !upFileRef.current?.files?.length || uploadMutation.isPending} loading={uploadMutation.isPending} color="green" className="text-sm py-2 shrink-0">
                    <Upload className="w-4 h-4 mr-1" /> Upload
                  </Button>
                </div>
              </div>
            )}

            {postExTab === 'hashdump' && (
              <div className="flex flex-col sm:flex-row items-start gap-2">
                <p className="text-xs text-gray-500 flex-1">Dump /etc/passwd and /etc/shadow hashes from the target.</p>
                <Button onClick={handleHashdump} disabled={hashdumpMutation.isPending} loading={hashdumpMutation.isPending} color="green" className="text-sm py-2 shrink-0">
                  <KeyRound className="w-4 h-4 mr-1" /> Run Hashdump
                </Button>
              </div>
            )}

            {postExTab === 'sysinfo' && (
              <div className="flex flex-col sm:flex-row items-start gap-2">
                <p className="text-xs text-gray-500 flex-1">Collect OS, kernel, user, and working directory from the target.</p>
                <Button onClick={handleSysinfo} disabled={sysinfoMutation.isPending} loading={sysinfoMutation.isPending} color="green" className="text-sm py-2 shrink-0">
                  <Cpu className="w-4 h-4 mr-1" /> Collect Sysinfo
                </Button>
              </div>
            )}

            {postExTab === 'cvescan' && (
              <div className="flex flex-col gap-3">
                <div className="flex flex-col sm:flex-row items-start gap-2">
                  <p className="text-xs text-gray-500 flex-1">
                    Run Kubesploit-style container CVE checks (runc, cgroup release_agent, kernel
                    exploits, privileged container, docker socket, Kubernetes posture) and launch
                    exploit PoCs through this session.
                  </p>
                  <Button onClick={handleCveScan} disabled={cveScanMutation.isPending} loading={cveScanMutation.isPending} color="green" className="text-sm py-2 shrink-0">
                    <Shield className="w-4 h-4 mr-1" /> Scan CVEs
                  </Button>
                </div>

                {cveScanMutation.isPending && <div className="text-xs text-gray-500 font-mono">Scanning target... (runs as a single shell script)</div>}

                {cveFindings && (
                  <>
                    <div className={clsx('text-xs font-mono', cveFindings.some((f) => f.status === 'vulnerable' || f.status === 'possibly') ? 'text-yellow-400' : 'text-green-400')}>
                      {cveScanSummary}
                    </div>
                    <div className="space-y-2">
                      {cveFindings.map((f) => (
                        <div key={f.cve} className={clsx('border rounded-lg p-3', f.status === 'vulnerable' ? 'border-red-900/50 bg-red-950/20' : f.status === 'possibly' ? 'border-yellow-900/50 bg-yellow-950/20' : 'border-gray-800/50 bg-gray-950/40')}>
                          <div className="flex items-center justify-between gap-2 flex-wrap">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-xs font-bold text-gray-200">{f.cve}</span>
                              <span className={clsx('text-xs px-1.5 py-0.5 rounded',
                                f.status === 'vulnerable' ? 'bg-red-400/10 text-red-400' :
                                f.status === 'possibly' ? 'bg-yellow-400/10 text-yellow-400' :
                                f.status === 'clean' ? 'bg-green-400/10 text-green-400' : 'bg-gray-700 text-gray-400',
                              )}>{f.status}</span>
                              <span className="text-xs px-1.5 py-0.5 rounded bg-gray-800/60 text-gray-400">{f.severity}</span>
                            </div>
                            <div className="flex items-center gap-1">
                              {EXPLOITABLE.includes(f.cve) && (
                                <>
                                  <select
                                    value={cveExploitTarget || f.cve}
                                    onChange={(e) => setCveExploitTarget(e.target.value)}
                                    className="bg-gray-800/80 border border-gray-700/60 rounded-lg text-xs px-2 py-1.5 text-gray-200 focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20 outline-none transition-colors"
                                  >
                                    {cveFindings.filter((x) => EXPLOITABLE.includes(x.cve)).map((x) => (
                                      <option key={x.cve} value={x.cve}>{x.cve}</option>
                                    ))}
                                  </select>
                                  <button
                                    onClick={() => handleCveExploit(cveExploitTarget || f.cve)}
                                    disabled={cveExploiting !== null}
                                    className="px-3 py-1.5 rounded-lg text-xs font-medium bg-webforge-600 text-white hover:bg-webforge-500 disabled:opacity-50 transition-colors"
                                  >
                                    {cveExploiting === f.cve ? 'Exploiting...' : 'Exploit'}
                                  </button>
                                </>
                              )}
                            </div>
                          </div>
                          <div className="text-xs text-gray-400 mt-2">{f.name}</div>
                          <div className="text-[11px] font-mono text-gray-500 mt-1 break-all">{f.detail}</div>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </div>
            )}

            {postExResult.length > 0 && (
              <div className="mt-4 space-y-2">
                {postExResult.slice(-10).map((r, i) => (
                  <OutputBlock key={i} title={r.title} maxHeight="max-h-48">
                    {r.body}
                  </OutputBlock>
                ))}
              </div>
            )}
          </div>
        </Card>
      )}

      <ConfirmDialog
        open={confirmKill !== null}
        title="Kill Session"
        message="Are you sure you want to kill this session? The target connection will be terminated."
        confirmLabel="Kill"
        destructive
        onConfirm={() => { if (confirmKill) killMutation.mutate(confirmKill); setConfirmKill(null) }}
        onCancel={() => setConfirmKill(null)}
      />

      <ConfirmDialog
        open={confirmStopListener !== null}
        title="Stop Listener"
        message="Are you sure you want to stop this listener? Active connections may be disrupted."
        confirmLabel="Stop"
        destructive
        onConfirm={() => { if (confirmStopListener) stopListenerMutation.mutate(confirmStopListener); setConfirmStopListener(null) }}
        onCancel={() => setConfirmStopListener(null)}
      />
    </div>
  )
}
