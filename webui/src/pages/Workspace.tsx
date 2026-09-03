import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { FolderOpen, Save, Trash2, Plus } from 'lucide-react'
import clsx from 'clsx'
import api from '../api'
import { PageHeader, Card, Input, Button, Spinner, EmptyState } from '../components/UI'
import { ConfirmDialog } from '../components/ConfirmDialog'
import type { WorkspacesResponse, WorkspaceLoadResponse } from '../types'

export default function Workspace() {
  const queryClient = useQueryClient()
  const [activeWs, setActiveWs] = useState('default')
  const [newWs, setNewWs] = useState('')
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)

  const { data: wsList } = useQuery({
    queryKey: ['workspaces'],
    queryFn: async () => { const res = await api.get<WorkspacesResponse>('/workspaces'); return res.data.workspaces },
  })

  const { data: wsData, isLoading } = useQuery({
    queryKey: ['workspace', activeWs],
    queryFn: async () => { const res = await api.post<WorkspaceLoadResponse>('/workspaces/load', { name: activeWs }); return res.data },
  })

  const saveMutation = useMutation({ mutationFn: async () => { await api.post('/workspaces/save', { name: activeWs }) } })

  const deleteMutation = useMutation({
    mutationFn: async (name: string) => { await api.delete(`/workspaces/${name}`) },
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['workspaces'] }); setActiveWs('default') },
  })

  const createMutation = useMutation({
    mutationFn: async (name: string) => { await api.post('/workspaces/save', { name }) },
    onSuccess: (_, name) => { queryClient.invalidateQueries({ queryKey: ['workspaces'] }); setActiveWs(name); setNewWs('') },
  })

  const workspaces: string[] = wsList || []

  return (
    <div className="space-y-4 sm:space-y-5">
      <PageHeader title="Workspace" subtitle="Manage workspaces, targets, and results" icon={<FolderOpen className="w-8 h-8" />} color="green" />

      <Card>
        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Workspaces</h3>
        <div className="flex flex-wrap gap-2 mb-3">
          {workspaces.map((ws) => (
            <div
              key={ws}
              className={clsx(
                'flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm cursor-pointer transition-all',
                activeWs === ws
                  ? 'bg-webforge-500/10 border-webforge-500/20 text-webforge-400'
                  : 'bg-gray-800/40 border-gray-700/40 text-gray-400 hover:border-gray-600',
              )}
              onClick={() => setActiveWs(ws)}
            >
              <FolderOpen className="w-3.5 h-3.5 shrink-0" />
              <span className="truncate">{ws}</span>
              {ws !== 'default' && (
                <button onClick={(e) => { e.stopPropagation(); setConfirmDelete(ws) }} className="text-gray-600 hover:text-red-400 ml-1 p-2 min-w-[36px] min-h-[36px] flex items-center justify-center rounded-lg hover:bg-red-500/5 transition-colors">
                  <Trash2 className="w-4 h-4" />
                </button>
              )}
            </div>
          ))}
        </div>
        <div className="flex gap-2">
          <Input value={newWs} onChange={(e) => setNewWs(e.target.value)} placeholder="New workspace name..." className="flex-1 min-w-0" onKeyDown={(e) => e.key === 'Enter' && newWs.trim() && createMutation.mutate(newWs.trim())} />
          <Button onClick={() => newWs.trim() && createMutation.mutate(newWs.trim())} disabled={!newWs.trim()} color="green" size="sm">
            <Plus className="w-3.5 h-3.5" /> <span className="hidden sm:inline">Create</span>
          </Button>
          <Button onClick={() => saveMutation.mutate()} variant="soft" color="gray" size="sm">
            <Save className="w-3.5 h-3.5" /> <span className="hidden sm:inline">Save</span>
          </Button>
        </div>
      </Card>

      {isLoading ? (
        <Spinner text="Loading workspace..." color="green" />
      ) : wsData && (
        <div className="space-y-4">
          <Card>
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Targets ({wsData.targets?.length || 0})</h3>
            {(!wsData.targets || wsData.targets.length === 0) ? (
              <p className="text-sm text-gray-600">No targets in this workspace.</p>
            ) : (
              <div className="space-y-1.5">
                {wsData.targets.map((t, i) => (
                  <div key={i} className="flex items-center justify-between px-3 py-2 bg-gray-800/30 border border-gray-800/40 rounded-lg gap-3">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-sm text-webforge-400">{t.host}</span>
                      <span className="text-xs text-gray-500">:{t.port}</span>
                      {t.ssl && <span className="text-[10px] px-1.5 py-0.5 rounded bg-webforge-500/10 text-webforge-400 border border-webforge-500/20">SSL</span>}
                      <span className="text-xs text-gray-600 truncate">{t.path}</span>
                    </div>
                    {t.fingerprint?.server && <span className="text-xs text-gray-500">{t.fingerprint.server}</span>}
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card>
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Results ({wsData.results?.length || 0})</h3>
            {(!wsData.results || wsData.results.length === 0) ? (
              <p className="text-sm text-gray-600">No results yet.</p>
            ) : (
              <div className="space-y-1.5">
                {wsData.results.map((r, i) => (
                  <pre key={i} className="output-block max-h-40">
                    {JSON.stringify(r, null, 2)}
                  </pre>
                ))}
              </div>
            )}
          </Card>
        </div>
      )}

      <ConfirmDialog
        open={confirmDelete !== null}
        title="Delete Workspace"
        message={`Are you sure you want to delete "${confirmDelete}"? This cannot be undone.`}
        confirmLabel="Delete"
        destructive
        onConfirm={() => { if (confirmDelete) deleteMutation.mutate(confirmDelete); setConfirmDelete(null) }}
        onCancel={() => setConfirmDelete(null)}
      />
    </div>
  )
}
