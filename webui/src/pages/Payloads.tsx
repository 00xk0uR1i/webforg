import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { Terminal, Copy, Plus, Zap, Shield, Bug } from 'lucide-react'
import api from '../api'
import { PageHeader, Card, Button, Spinner } from '../components/UI'
import { useCopy } from '../hooks/useCopy'
import type { Shell, Encoder, EncodersResponse, ShellsResponse, PayloadGenerateResponse } from '../types'

const LANGS = ['all', 'bash', 'python', 'php', 'perl', 'ruby', 'node', 'nc', 'powershell', 'c', 'java', 'lua']

export default function Payloads() {
  const [lhost, setLhost] = useState('127.0.0.1')
  const [lport, setLport] = useState('4444')
  const [lang, setLang] = useState('all')
  const [encoder, setEncoder] = useState('none')

  const [payloadName, setPayloadName] = useState('revshell_bash')
  const [active, setActive] = useState<{ cmd: string; raw: string; name: string } | null>(null)
  const { copy, copied } = useCopy()

  const { data: encodersData } = useQuery({
    queryKey: ['encoders'],
    queryFn: async () => {
      const res = await api.get<EncodersResponse>('/encoders')
      return res.data.encoders
    },
  })

  const shellsMutation = useMutation({
    mutationFn: async () => {
      const res = await api.get<ShellsResponse>('/shells/generate', { params: { lhost, lport, lang, encoder } })
      return res.data
    },
  })

  const payloadMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post<PayloadGenerateResponse>('/payloads/generate', { name: payloadName, lhost, lport, encoder })
      return res.data
    },
  })

  const shells = shellsMutation.data?.shells || []
  const listenerCmd = shellsMutation.data?.listener || `nc -lvnp ${lport}`
  const payload = payloadMutation.data

  const genShells = () => shellsMutation.mutate()

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader
        title="Payload Generator"
        subtitle="Reverse shells & web payloads with encoder-based obfuscation for evasion"
        icon={<Zap className="w-8 h-8" />}
        color="amber"
      >
        <div className="flex items-start gap-2 px-1">
          <Shield className="w-4 h-4 text-gray-500 shrink-0 mt-0.5" />
          <p className="text-xs text-gray-500">Generate obfuscated payloads with base64, hex, XOR, reversed, and URL encoders to bypass simple AV/IDS signatures.</p>
        </div>
      </PageHeader>

      <Card>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <div>
            <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5">LHOST</div>
            <input
              type="text"
              value={lhost}
              onChange={(e) => setLhost(e.target.value)}
              placeholder="Your IP"
              className="w-full px-3 py-2.5 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white placeholder-gray-500 focus:border-amber-500/60 focus:ring-1 focus:ring-amber-500/20 outline-none transition-colors min-h-[40px]"
            />
          </div>
          <div>
            <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5">LPORT</div>
            <input
              type="text"
              value={lport}
              onChange={(e) => setLport(e.target.value)}
              placeholder="4444"
              className="w-full px-3 py-2.5 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white placeholder-gray-500 focus:border-amber-500/60 focus:ring-1 focus:ring-amber-500/20 outline-none transition-colors min-h-[40px]"
            />
          </div>
          <div>
            <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5">Language</div>
            <select
              value={lang}
              onChange={(e) => setLang(e.target.value)}
              className="w-full px-3 py-2.5 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white focus:border-amber-500/60 focus:ring-1 focus:ring-amber-500/20 outline-none transition-colors min-h-[40px]"
            >
              {LANGS.map((l) => <option key={l} value={l}>{l === 'all' ? 'All languages' : l}</option>)}
            </select>
          </div>
          <div>
            <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5">Encoder</div>
            <select
              value={encoder}
              onChange={(e) => setEncoder(e.target.value)}
              className="w-full px-3 py-2.5 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white focus:border-amber-500/60 focus:ring-1 focus:ring-amber-500/20 outline-none transition-colors min-h-[40px]"
            >
              {(encodersData || []).map((e) => <option key={e.name} value={e.name}>{e.name}</option>)}
            </select>
          </div>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Button color="amber" onClick={genShells} loading={shellsMutation.isPending}>
            <Terminal className="w-4 h-4 mr-2" /> Generate Reverse Shells
          </Button>
          {encoder !== 'none' && (
            <span className="text-[11px] text-amber-400">
              {encodersData?.find((e) => e.name === encoder)?.description}
            </span>
          )}
        </div>
      </Card>

      {copied && (
        <div className="fixed bottom-6 right-6 z-50 px-4 py-2 rounded-lg bg-gray-800 border border-gray-700 text-sm text-gray-200 shadow-lg">
          Copied {copied}
        </div>
      )}

      {shellsMutation.isPending && (
        <Card><Spinner text="Generating payloads..." color="amber" /></Card>
      )}

      {shells.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between px-1">
            <div className="text-[11px] font-bold uppercase tracking-widest text-gray-500">
              Reverse Shells ({shells.length}) — encoder: {shellsMutation.data?.encoder}
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-gray-600">Listener:</span>
              <button onClick={() => copy(listenerCmd, 'listener')} className="text-xs font-mono text-cyan-400 hover:underline flex items-center gap-1">
                {listenerCmd} <Copy className="w-3 h-3" />
              </button>
            </div>
          </div>
          {shells.map((s) => (
            <Card key={s.name}>
              <div className="flex items-start gap-2">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className="text-sm font-medium text-gray-100">{s.name}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-500">{s.language}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-500">{s.os}</span>
                  </div>
                  <div className="bg-gray-950/60 border border-gray-800 rounded-lg p-3">
                    <pre className="text-[11px] text-gray-300 font-mono whitespace-pre-wrap break-all leading-relaxed">{s.cmd}</pre>
                  </div>
                  <div className="text-[10px] text-gray-600 mt-1.5">{s.description}</div>
                </div>
                <button
                  onClick={() => { setActive({ cmd: s.cmd, raw: s.raw, name: s.name }); copy(s.cmd, s.name) }}
                  className="p-2 rounded-lg text-gray-500 hover:text-white hover:bg-gray-800 transition-colors min-w-[36px] min-h-[36px] flex items-center justify-center"
                  title="Copy payload"
                >
                  <Copy className="w-4 h-4" />
                </button>
              </div>
            </Card>
          ))}
        </div>
      )}

      {active && (
        <Card>
          <div className="flex items-center gap-2 mb-2">
            <Bug className="w-4 h-4 text-amber-400" />
            <div className="text-[11px] font-bold uppercase tracking-widest text-gray-500">Show Raw — {active.name}</div>
            <button onClick={() => copy(active.raw, 'raw')} className="ml-auto flex items-center gap-1 text-xs text-gray-400 hover:text-white">
              <Copy className="w-3.5 h-3.5" /> Copy raw
            </button>
          </div>
          <pre className="bg-gray-950/60 border border-gray-800 rounded-lg p-3 text-[11px] text-gray-300 font-mono whitespace-pre-wrap break-all">{active.raw}</pre>
        </Card>
      )}

      {/* Web payload generator */}
      <Card>
        <div className="flex items-center gap-2 mb-3">
          <Plus className="w-4 h-4 text-amber-400" />
          <div className="text-[11px] font-bold uppercase tracking-widest text-gray-500">Web Payload</div>
        </div>
        <div className="flex flex-col sm:flex-row gap-3">
          <select
            value={payloadName}
            onChange={(e) => setPayloadName(e.target.value)}
            className="px-3 py-2.5 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white focus:border-amber-500/60 focus:ring-1 focus:ring-amber-500/20 outline-none transition-colors min-h-[44px]"
          >
            <option value="revshell_bash">Bash reverse shell (PHP-friendly)</option>
            <option value="revshell_python">Python reverse shell</option>
            <option value="revshell_php">PHP reverse shell</option>
            <option value="revshell_node">Node.js reverse shell</option>
            <option value="revshell_jsp">JSP reverse shell</option>
          </select>
          <Button color="amber" onClick={() => payloadMutation.mutate()} loading={payloadMutation.isPending} className="shrink-0">
            Generate Web Payload
          </Button>
        </div>
        {payload && (
          <div className="mt-3 space-y-3">
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] text-gray-500 uppercase tracking-wider">Payload — encoder: {payload.encoder}</span>
                <button onClick={() => copy(payload.payload, 'payload')} className="flex items-center gap-1 text-xs text-gray-400 hover:text-white">
                  <Copy className="w-3.5 h-3.5" /> Copy
                </button>
              </div>
              <pre className="bg-gray-950/60 border border-gray-800 rounded-lg p-3 text-[11px] text-gray-300 font-mono whitespace-pre-wrap break-all leading-relaxed">{payload.payload}</pre>
              {payload.note && <div className="text-[11px] text-amber-400 mt-1">{payload.note}</div>}
            </div>
            {payload.one_liner && (
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] text-gray-500 uppercase tracking-wider">One-liner</span>
                  <button onClick={() => copy(payload.one_liner, 'one-liner')} className="flex items-center gap-1 text-xs text-gray-400 hover:text-white">
                    <Copy className="w-3.5 h-3.5" /> Copy
                  </button>
                </div>
                <pre className="bg-gray-950/60 border border-gray-800 rounded-lg p-3 text-[11px] text-gray-300 font-mono whitespace-pre-wrap break-all">{payload.one_liner}</pre>
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  )
}
