import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Globe, Fingerprint } from 'lucide-react'
import clsx from 'clsx'
import api from '../api'
import { PageHeader, Card, Input, Table, Spinner, EmptyState } from '../components/UI'
import type { WorkspaceTarget, WorkspaceLoadResponse, FingerprintResponse } from '../types'

export default function Targets() {
  const queryClient = useQueryClient()
  const [host, setHost] = useState('')
  const [port, setPort] = useState('80')
  const [ssl, setSsl] = useState(false)
  const [scanResult, setScanResult] = useState<Record<string, unknown> | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['targets'],
    queryFn: async () => {
      const res = await api.post<WorkspaceLoadResponse>('/workspaces/load', { name: 'default' })
      return res.data.targets || []
    },
  })

  const fingerprintMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post<FingerprintResponse>('/fingerprint', { host, port: parseInt(port), ssl, path: '/' })
      return res.data.fingerprint
    },
    onSuccess: (fp) => setScanResult(fp),
  })

  const targets: WorkspaceTarget[] = data || []

  return (
    <div className="space-y-4 sm:space-y-5">
      <PageHeader title="Targets" subtitle="Manage and fingerprint target hosts" icon={<Globe className="w-8 h-8" />} color="green">
        <Card>
          <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-end">
            <Input label="Host" value={host} onChange={(e) => setHost(e.target.value)} placeholder="192.168.1.1 or example.com" className="flex-1 min-w-0 font-mono" />
            <Input label="Port" value={port} onChange={(e) => setPort(e.target.value)} className="w-full sm:w-24 font-mono" />
            <div className="flex items-center gap-2 py-2 sm:py-0">
              <input type="checkbox" id="ssl-check" checked={ssl} onChange={(e) => setSsl(e.target.checked)} className="accent-webforge-500" />
              <label htmlFor="ssl-check" className="text-sm text-gray-400">SSL</label>
            </div>
            <button
              onClick={() => host.trim() && fingerprintMutation.mutate()}
              disabled={!host.trim() || fingerprintMutation.isPending}
              className="flex items-center justify-center gap-2 px-4 py-2.5 bg-webforge-600 rounded-lg text-sm font-medium hover:bg-webforge-500 transition-colors disabled:opacity-50 min-h-[40px]"
            >
              <Fingerprint className="w-4 h-4" />
              {fingerprintMutation.isPending ? 'Scanning...' : 'Fingerprint'}
            </button>
          </div>
        </Card>
      </PageHeader>

      {fingerprintMutation.isPending && <Spinner text="Fingerprinting target..." color="green" />}

      {scanResult && (
        <Card className="border-webforge-500/20">
          <h3 className="text-xs font-semibold text-webforge-400 mb-3 truncate">Scan Result: {host}</h3>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
            {Object.entries(scanResult).map(([key, val]) => {
              if (key === 'raw_headers' || !val) return null
              const display = Array.isArray(val) ? val.join(', ') : String(val)
              return (
                <div key={key} className="bg-gray-800/40 border border-gray-800/40 rounded-lg p-2">
                  <div className="text-xs text-gray-500 capitalize">{key.replace(/_/g, ' ')}</div>
                  <div className="text-sm font-mono text-gray-200 truncate">{display}</div>
                </div>
              )
            })}
          </div>
        </Card>
      )}

      {isLoading ? (
        <Spinner text="Loading targets..." color="green" />
      ) : targets.length === 0 ? (
        <EmptyState
          icon={<Globe className="w-8 h-8" />}
          title="No targets yet"
          description="Fingerprint a host above to add one."
        />
      ) : (
        <Table
          title={`${targets.length} Target(s)`}
          color="green"
          columns={['Host', 'Port', 'SSL', 'Path', 'Technologies']}
          rows={targets.map((t) => [
            <span key="h" className="font-mono text-webforge-400">{t.host}</span>,
            <span key="p" className="font-mono">{t.port}</span>,
            t.ssl ? <span className="text-webforge-400">Yes</span> : <span className="text-gray-600">No</span>,
            <span key="pa" className="font-mono text-gray-500">{t.path}</span>,
            t.fingerprint?.technologies?.join(', ') || '-',
          ])}
        />
      )}
    </div>
  )
}
