import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Radar, Network, Copy, Crosshair, Server } from 'lucide-react'
import clsx from 'clsx'
import api from '../api'
import { PageHeader, Card, Button, Spinner, Stats, EmptyState, OutputBlock } from '../components/UI'
import { useCopy } from '../hooks/useCopy'
import type { PortScanResponse } from '../types'

const PRESETS = [
  { label: 'Common (60 ports)', value: 'common' },
  { label: 'All 1-65535', value: 'all' },
  { label: 'Custom', value: 'custom' },
]

export default function PortScanner() {
  const [host, setHost] = useState('')
  const [preset, setPreset] = useState('common')
  const [custom, setCustom] = useState('')
  const [timeout, setTimeoutVal] = useState(1.5)
  const [grab, setGrab] = useState(true)
  const [useSsl, setUseSsl] = useState(false)

  const mutation = useMutation({
    mutationFn: async (payload: Record<string, unknown>) => {
      const res = await api.post<PortScanResponse>('/portscan/scan', payload)
      return res.data
    },
  })

  const run = mutation.data
  const { copy } = useCopy()

  const handleScan = () => {
    if (!host.trim()) return
    const ports = preset === 'custom' ? custom.trim() : preset
    mutation.mutate({ host: host.trim(), ports, timeout, grab_banners: grab, use_ssl: useSsl })
  }

  const copyResults = async () => {
    if (!run) return
    const lines = [
      `Port scan — ${run.host} (${run.duration}s)`,
      `${run.ports_scanned} scanned, ${run.ports_open} open`,
      '',
      ...run.results.map(
        (r) => `${r.port}/tcp  open  ${r.service || '?'}${r.product ? '  ' + r.product : ''}${r.version ? ' ' + r.version : ''}`
      ),
    ]
    await copy(lines.join('\n'))
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader
        title="Port Scanner"
        subtitle="Threaded TCP connect scan with banner grabbing and service identification"
        icon={<Radar className="w-8 h-8" />}
        color="cyan"
      >
        <div className="flex items-start gap-2 px-1">
          <Network className="w-4 h-4 text-gray-500 shrink-0 mt-0.5" />
          <p className="text-xs text-gray-500">Connect-based scanning — safe, accurate, and banner-aware. Includes service fingerprinting from banners.</p>
        </div>
      </PageHeader>

      <Card>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="relative md:col-span-2">
            <Server className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              placeholder="Target host — IP or hostname, e.g. 10.10.10.5"
              className="w-full pl-10 pr-4 py-3 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white placeholder-gray-500 focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors min-h-[44px]"
            />
          </div>

          <div className="flex flex-wrap gap-1.5">
            {PRESETS.map((p) => (
              <button
                key={p.value}
                onClick={() => setPreset(p.value)}
                className={clsx(
                  'text-xs px-3 py-2 rounded-lg border transition-colors min-h-[36px]',
                  preset === p.value
                    ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-400'
                    : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200',
                )}
              >
                {p.label}
              </button>
            ))}
          </div>

          {preset === 'custom' && (
            <input
              type="text"
              value={custom}
              onChange={(e) => setCustom(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              placeholder="Ports — e.g. 80,443,8000-8100"
              className="w-full px-4 py-3 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white placeholder-gray-500 focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors min-h-[44px]"
            />
          )}

          <div className="flex flex-wrap items-center gap-4 md:col-span-2">
            <label className="flex items-center gap-2 text-xs text-gray-400">
              Timeout
              <input
                type="number"
                min={0.1}
                step={0.1}
                value={timeout}
                onChange={(e) => setTimeoutVal(parseFloat(e.target.value) || 1.5)}
                className="w-20 px-2 py-1.5 bg-gray-800/80 border border-gray-700/60 rounded-md text-sm text-white focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors"
              />
              s
            </label>
            <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer select-none">
              <input type="checkbox" checked={grab} onChange={(e) => setGrab(e.target.checked)} className="accent-cyan-500" />
              Banner grab
            </label>
            <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer select-none">
              <input type="checkbox" checked={useSsl} onChange={(e) => setUseSsl(e.target.checked)} className="accent-cyan-500" />
              Force TLS
            </label>
            <Button color="cyan" onClick={handleScan} loading={mutation.isPending} disabled={!host.trim()} className="ml-auto">
              <Crosshair className="w-4 h-4 mr-2" /> {mutation.isPending ? 'Scanning...' : 'Scan'}
            </Button>
          </div>
        </div>
      </Card>

      {mutation.isPending && (
        <Card>
          <Spinner text={`Scanning ${host}...`} color="cyan" />
        </Card>
      )}

      {run && !mutation.isPending && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <Stats stats={[
              { label: 'Ports Scanned', value: run.ports_scanned },
              { label: 'Open', value: run.ports_open, color: run.ports_open > 0 ? 'green' : undefined },
              { label: 'Duration', value: `${run.duration}s` },
            ]} />
            <button
              onClick={copyResults}
              className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-colors border border-gray-700 min-h-[36px]"
            >
              <Copy className="w-3.5 h-3.5" /> Copy
            </button>
          </div>

          {run.results.length === 0 ? (
            <EmptyState
              icon={<Network className="w-10 h-10" />}
              title="No open ports found"
              description={`Host ${run.host} returned no open ports for the given range.`}
            />
          ) : (
            <div className="space-y-2">
              {run.results.map((r) => (
                <Card key={r.port}>
                  <div className="flex items-start gap-3">
                    <div className="w-16 shrink-0">
                      <div className="text-lg font-mono font-bold text-cyan-400">{r.port}</div>
                      <div className="text-[10px] text-gray-600 uppercase">/tcp</div>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-medium text-gray-100">{r.service || 'unknown'}</span>
                        {r.product && <span className="text-xs text-gray-400">{r.product}{r.version ? ` ${r.version}` : ''}</span>}
                        <span className="text-[10px] px-1.5 py-0.5 rounded font-bold bg-green-400/10 text-green-400">OPEN</span>
                        {r.ssl && <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-400/10 text-amber-400">SSL</span>}
                      </div>
                      {r.banner && (
                        <OutputBlock className="mt-2" maxHeight="max-h-none">{r.banner}</OutputBlock>
                      )}
                      {!r.banner && (
                        <div className="mt-1 text-[11px] text-gray-600">No banner captured</div>
                      )}
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      {!run && !mutation.isPending && (
        <EmptyState
          icon={<Radar className="w-12 h-12" />}
          title="TCP Port Scanner"
          description="Enter a host to enumerate open ports and grab service banners. Uses threaded TCP connects with configurable timeout, TLS probing, and banner-based service fingerprinting."
        />
      )}
    </div>
  )
}
