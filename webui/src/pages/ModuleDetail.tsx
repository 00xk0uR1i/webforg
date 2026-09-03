import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useParams, useNavigate } from 'react-router-dom'
import { useState } from 'react'
import { ArrowLeft, Play, CheckCircle, AlertTriangle, Terminal } from 'lucide-react'
import clsx from 'clsx'
import api from '../api'
import { Card, Button, Input, Spinner } from '../components/UI'
import { ConfirmDialog } from '../components/ConfirmDialog'
import type { ModuleInfo, ModuleCheckResult, ModuleExploitResponse, SetOptionResponse } from '../types'

export default function ModuleDetail() {
  const { modulePath } = useParams<{ modulePath: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const decodedPath = decodeURIComponent(modulePath || '')
  const [optionValues, setOptionValues] = useState<Record<string, string>>({})
  const [result, setResult] = useState<
    { type: 'check'; data: ModuleCheckResult } | { type: 'exploit'; data: ModuleExploitResponse } | null
  >(null)
  const [confirmAction, setConfirmAction] = useState<'exploit' | 'run' | null>(null)

  const { data: mod, isLoading } = useQuery({
    queryKey: ['module', decodedPath],
    queryFn: async () => { const res = await api.get<ModuleInfo>(`/modules/${decodedPath}`); return res.data },
  })

  const checkMutation = useMutation({
    mutationFn: async () => {
      for (const [name, value] of Object.entries(optionValues)) { if (value) await api.post<SetOptionResponse>('/modules/set-option', { module_path: decodedPath, name, value }) }
      const res = await api.post<ModuleCheckResult>('/modules/check', { module_path: decodedPath }); return res.data
    },
    onSuccess: (data) => setResult({ type: 'check', data }),
  })

  const exploitMutation = useMutation({
    mutationFn: async () => {
      for (const [name, value] of Object.entries(optionValues)) { if (value) await api.post<SetOptionResponse>('/modules/set-option', { module_path: decodedPath, name, value }) }
      const res = await api.post<ModuleExploitResponse>('/modules/exploit', { module_path: decodedPath }); return res.data
    },
    onSuccess: (data) => { setResult({ type: 'exploit', data }); if (data.session_id) queryClient.invalidateQueries({ queryKey: ['sessions'] }) },
  })

  const runMutation = useMutation({
    mutationFn: async () => {
      for (const [name, value] of Object.entries(optionValues)) { if (value) await api.post<SetOptionResponse>('/modules/set-option', { module_path: decodedPath, name, value }) }
      const res = await api.post<ModuleExploitResponse>('/modules/run', { module_path: decodedPath }); return res.data
    },
    onSuccess: (data) => setResult({ type: 'exploit', data }),
  })

  const isExploit = mod?.type === 'exploit'
  const handleExploit = () => {
    if (!confirmAction) setConfirmAction(isExploit ? 'exploit' : 'run')
  }

  if (isLoading) return <Spinner text="Loading module..." color="green" />
  if (!mod) return <div className="text-center py-12"><p className="text-red-400">Module not found</p><button onClick={() => navigate('/')} className="text-webforge-400 mt-2 hover:underline">Back to modules</button></div>

  const isRunning = checkMutation.isPending || exploitMutation.isPending || runMutation.isPending

  return (
    <div className="space-y-4 sm:space-y-5">
      <button onClick={() => navigate(-1)} className="flex items-center gap-2 px-3 py-2 min-h-[40px] text-sm text-gray-400 hover:text-gray-200 transition-colors rounded-lg hover:bg-gray-800/60">
        <ArrowLeft className="w-4 h-4" /> Back
      </button>

      <Card>
        <h2 className="text-lg font-bold text-gray-100">{mod.name}</h2>
        <p className="text-sm text-gray-400 mt-1 leading-relaxed">{mod.description}</p>
        <div className="flex items-center gap-3 mt-3 text-sm flex-wrap">
          <span className="text-gray-500">by {mod.author}</span>
          <span className={clsx('text-xs px-2 py-0.5 rounded font-medium bg-gray-800/60 border border-gray-700/40', mod.rank === 'excellent' ? 'text-yellow-400' : mod.rank === 'good' ? 'text-webforge-400' : 'text-gray-400')}>{mod.rank.toUpperCase()}</span>
          {mod.cve && <span className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-400 font-mono border border-red-500/20">{mod.cve}</span>}
          {mod.cvss != null && <span className="text-yellow-400 text-xs">CVSS {mod.cvss}</span>}
          {mod.disclosure_date && <span className="text-gray-500 text-xs hidden sm:inline">Disclosed: {mod.disclosure_date}</span>}
        </div>
      </Card>

      <Card>
        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">Options</h3>
        <div className="space-y-3">
          {Object.entries(mod.options).map(([name, opt]) => (
            <div key={name} className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4">
              <label className="sm:w-32 text-sm font-mono text-gray-400 shrink-0">
                {name}{opt.required && <span className="text-red-400 ml-1">*</span>}
              </label>
              <input type="text" placeholder={opt.value != null ? String(opt.value) : opt.description} value={optionValues[name] || ''} onChange={(e) => setOptionValues((prev) => ({ ...prev, [name]: e.target.value }))} className="flex-1 px-3 py-2 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm font-mono focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20 transition-colors" />
              <span className="text-xs text-gray-600 sm:w-40 truncate">{opt.description}</span>
            </div>
          ))}
        </div>
        <div className="flex gap-3 mt-6">
          {isExploit && (
            <>
              <Button onClick={() => checkMutation.mutate()} disabled={isRunning} variant="soft" color="yellow">
                <CheckCircle className="w-4 h-4" /> {checkMutation.isPending ? 'Checking...' : 'Check'}
              </Button>
              <Button onClick={handleExploit} disabled={isRunning} loading={exploitMutation.isPending}>Exploit</Button>
            </>
          )}
          {!isExploit && <Button onClick={handleExploit} disabled={isRunning} loading={runMutation.isPending}>Run</Button>}
        </div>
      </Card>

      {result && (
        <Card>
          <div className="flex items-center gap-2 mb-3">
            {result.type === 'check' ? <CheckCircle className="w-4 h-4 text-cyan-400" /> : <Terminal className="w-4 h-4 text-webforge-400" />}
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">{result.type === 'check' ? 'Check Result' : 'Exploit Result'}</h3>
          </div>
          {result.type === 'check' ? (
            <div className={clsx('p-3 rounded-lg text-sm border', result.data.vulnerable ? 'bg-red-500/10 border-red-500/20 text-red-300' : 'bg-gray-800/60 border-gray-700/40 text-gray-400')}>
              <div className="flex items-center gap-2">
                {result.data.vulnerable ? <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" /> : <CheckCircle className="w-4 h-4 shrink-0" />}
                <span className="font-medium">{result.data.vulnerable ? 'VULNERABLE' : 'Not Vulnerable'}</span>
              </div>
              <p className="mt-2 text-xs opacity-75">{result.data.details}</p>
            </div>
          ) : (
            <div className={clsx('p-3 rounded-lg text-sm border', result.data.success ? 'bg-webforge-500/10 border-webforge-500/20 text-webforge-300' : 'bg-red-500/10 border-red-500/20 text-red-300')}>
              <div className="flex items-center gap-2 mb-2">
                <span className="font-medium">{result.data.success ? 'SUCCESS' : 'FAILED'}</span>
                {result.data.session_id && <span className="text-xs px-2 py-0.5 bg-webforge-500/15 rounded border border-webforge-500/20">Session: {result.data.session_id}</span>}
              </div>
              <pre className="text-xs whitespace-pre-wrap font-mono opacity-75 break-all">{typeof result.data.output === 'string' ? result.data.output : JSON.stringify(result.data, null, 2)}</pre>
            </div>
          )}
        </Card>
      )}

      <ConfirmDialog
        open={confirmAction !== null}
        title={confirmAction === 'exploit' ? 'Run Exploit' : 'Run Module'}
        message="Are you sure you want to run this module? This may execute code on the target system."
        confirmLabel={confirmAction === 'exploit' ? 'Exploit' : 'Run'}
        destructive
        onConfirm={() => {
          if (confirmAction === 'exploit') exploitMutation.mutate()
          else if (confirmAction === 'run') runMutation.mutate()
          setConfirmAction(null)
        }}
        onCancel={() => setConfirmAction(null)}
      />
    </div>
  )
}
