import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Loader, Play, X, Eye } from 'lucide-react'
import clsx from 'clsx'
import api from '../api'
import { PageHeader, Card, Button, Spinner, EmptyState } from '../components/UI'
import { StatusBadge } from '../features/common/badges'
import type { Job, JobFull, JobListResponse, JobSubmitResponse } from '../types'

const ACTIONS = [
  { value: 'portscan', label: 'Port Scan' },
  { value: 'osint', label: 'OSINT Account Scan' },
  { value: 'dork', label: 'Dork Search' },
  { value: 'cve_update', label: 'CVE DB Update' },
]

export default function Jobs() {
  const qc = useQueryClient()
  const [action, setAction] = useState('portscan')
  const [params, setParams] = useState<Record<string, string>>({})
  const [viewing, setViewing] = useState<JobFull | null>(null)

  const { data } = useQuery({
    queryKey: ['jobs'],
    queryFn: async () => {
      const res = await api.get<JobListResponse>('/jobs')
      return res.data.jobs
    },
    refetchInterval: 2000,
  })

  const submitMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post<JobSubmitResponse>('/jobs/submit', { action, params })
      return res.data
    },
    onSuccess: () => {
      setParams({})
      qc.invalidateQueries({ queryKey: ['jobs'] })
    },
  })

  const cancelMutation = useMutation({
    mutationFn: async (id: string) => api.post(`/jobs/${id}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['jobs'] }),
  })

  const fetchResult = async (id: string) => {
    const res = await api.get<JobFull>(`/jobs/${id}`, { params: { include_result: true } })
    setViewing(res.data)
  }

  const paramsFor = (a: string) => {
    if (a === 'portscan') return [
      { k: 'host', ph: 'Target host' },
      { k: 'ports', ph: 'common | all | 80,443,8000-8100' },
    ]
    if (a === 'osint') return [
      { k: 'query', ph: 'Username or email' },
      { k: 'mode', ph: 'username | email' },
    ]
    if (a === 'dork') return [
      { k: 'query', ph: 'Search query' },
      { k: 'engine', ph: 'ddg | bing | brave | google' },
    ]
    return []
  }

  const set = (k: string, v: string) => setParams((p) => ({ ...p, [k]: v }))

  return (
    <div className="space-y-4 sm:space-y-5">
      <PageHeader
        title="Job Center"
        subtitle="Run long scans and tasks in the background with live progress tracking"
        icon={<Loader className="w-8 h-8" />}
        color="cyan"
      >
        <div className="flex items-start gap-2 px-1">
          <p className="text-xs text-gray-500">Long operations run on background threads — the UI stays responsive and you can poll progress or cancel anytime.</p>
        </div>
      </PageHeader>

      <Card>
        <div className="flex flex-wrap gap-2 mb-3">
          {ACTIONS.map((a) => (
            <button
              key={a.value}
              onClick={() => { setAction(a.value); setParams({}) }}
              className={clsx(
                'text-xs px-3 py-2 rounded-lg border transition-colors min-h-[36px] font-medium',
                action === a.value
                  ? 'bg-cyan-500/10 border-cyan-500/20 text-cyan-400'
                  : 'bg-gray-800/40 border-gray-700/40 text-gray-500 hover:text-gray-300',
              )}
            >
              {a.label}
            </button>
          ))}
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {paramsFor(action).map((p) => (
            <input
              key={p.k}
              type="text"
              value={params[p.k] || ''}
              onChange={(e) => set(p.k, e.target.value)}
              placeholder={p.ph}
              className="px-3 py-2.5 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white placeholder-gray-500 focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors min-h-[40px]"
            />
          ))}
          <Button color="cyan" onClick={() => submitMutation.mutate()} loading={submitMutation.isPending}>
            <Play className="w-4 h-4" /> Submit Job
          </Button>
        </div>
      </Card>

      {submitMutation.isPending && (
        <Card><Spinner text="Submitting job..." color="cyan" /></Card>
      )}

      <div className="space-y-2">
        {(data || []).length === 0 ? (
          <EmptyState
            icon={<Loader className="w-8 h-8" />}
            title="No jobs yet"
            description="Submit a job above to run long operations in the background."
          />
        ) : (
          (data || []).map((j) => (
            <Card key={j.id}>
              <div className="flex items-center gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1.5">
                    <span className="text-sm font-medium text-gray-100">{j.name}</span>
                    <StatusBadge status={j.status} variant="job" />
                    <span className="text-[10px] text-gray-600 font-mono">{j.id}</span>
                  </div>
                  <div className="h-1.5 bg-gray-800/60 rounded-full overflow-hidden">
                    <div
                      className={clsx(
                        'h-full rounded-full transition-all duration-500',
                        j.status === 'error' ? 'bg-red-500' : j.status === 'done' ? 'bg-green-500' : 'bg-cyan-500',
                      )}
                      style={{ width: `${j.progress}%` }}
                    />
                  </div>
                  <div className="text-[11px] text-gray-500 mt-1.5 flex items-center justify-between">
                    <span>{j.message}</span>
                    <span className="tabular-nums">{j.progress}%</span>
                  </div>
                </div>
                <div className="flex flex-col gap-1.5">
                  {j.status === 'done' && (
                    <button
                      onClick={() => fetchResult(j.id)}
                      className="text-[11px] px-2.5 py-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 border border-gray-700/40 flex items-center gap-1 min-h-[32px] transition-colors"
                    >
                      <Eye className="w-3 h-3" /> Result
                    </button>
                  )}
                  {(j.status === 'queued' || j.status === 'running') && (
                    <button
                      onClick={() => cancelMutation.mutate(j.id)}
                      className="text-[11px] px-2.5 py-1.5 rounded-lg text-gray-400 hover:text-red-400 hover:bg-red-500/5 border border-gray-700/40 flex items-center gap-1 min-h-[32px] transition-colors"
                    >
                      <X className="w-3 h-3" /> Cancel
                    </button>
                  )}
                </div>
              </div>
              {j.error && <div className="mt-2 text-[11px] text-red-400">{j.error}</div>}
            </Card>
          ))
        )}
      </div>

      {viewing && (
        <Card>
          <div className="flex items-center gap-2 mb-2">
            <Eye className="w-4 h-4 text-cyan-400" />
            <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Job Result — {viewing.name}</div>
            <button onClick={() => setViewing(null)} className="ml-auto text-gray-500 hover:text-white p-1 rounded-lg hover:bg-gray-800 transition-colors"><X className="w-4 h-4" /></button>
          </div>
          <pre className="output-block max-h-96">
            {JSON.stringify(viewing.result, null, 2)}
          </pre>
        </Card>
      )}
    </div>
  )
}
