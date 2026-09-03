import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { KeyRound, Plus, Search, Trash2, Eye, EyeOff, Copy, Vault } from 'lucide-react'
import api from '../api'
import { PageHeader, Card, Button, Stats, EmptyState } from '../components/UI'
import type { CredRow, CredListResponse, CredAddResponse, CredDeleteResponse, CredClearResponse } from '../types'

export default function CredVault() {
  const qc = useQueryClient()
  const [query, setQuery] = useState('')
  const [revealed, setRevealed] = useState<Set<number>>(new Set())
  const [showAdd, setShowAdd] = useState(false)
  const [add, setAdd] = useState({ target: '', username: '', password: '', source: 'manual' })
  const [toast, setToast] = useState('')

  const { data } = useQuery({
    queryKey: ['creds-db', query],
    queryFn: async () => {
      const res = await api.get<CredListResponse>('/creds-db/list', { params: { q: query || undefined } })
      return res.data
    },
  })

  const addMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post<CredAddResponse>('/creds-db/add', add)
      return res.data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['creds-db'] })
      setAdd({ target: '', username: '', password: '', source: 'manual' })
      setShowAdd(false)
    },
  })

  const delMutation = useMutation({
    mutationFn: async (id: number) => api.post<CredDeleteResponse>('/creds-db/delete', { id }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['creds-db'] }),
  })

  const clearMutation = useMutation({
    mutationFn: async () => api.post<CredClearResponse>('/creds-db/clear'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['creds-db'] }),
  })

  const flash = (msg: string) => {
    setToast(msg)
    setTimeout(() => setToast(''), 2000)
  }

  const copy = async (text: string) => {
    await navigator.clipboard.writeText(text)
    flash('Copied')
  }

  const toggleReveal = (id: number) => {
    setRevealed((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader
        title="Credential Vault"
        subtitle="Persistent SQLite credential store — every brute force, spray, stuffing and enum hit is saved here automatically"
        icon={<KeyRound className="w-8 h-8" />}
        color="amber"
      >
        <div className="flex items-start gap-2 px-1">
          <Vault className="w-4 h-4 text-gray-500 shrink-0 mt-0.5" />
          <p className="text-xs text-gray-500">Credentials found by auth modules are auto-imported with their target. Search, export, or feed them back into spray/stuffing.</p>
        </div>
      </PageHeader>

      <Stats stats={[
        { label: 'Total Credentials', value: data?.total ?? 0, color: 'green' },
        { label: 'Loaded', value: data?.count ?? 0 },
        { label: 'Sources', value: data?.creds?.length ? new Set(data.creds.map((c) => c.source)).size : 0 },
      ]} />

      <Card>
        <div className="flex flex-col sm:flex-row gap-3 items-stretch">
          <div className="relative flex-1 min-w-0">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search target, username or password..."
              className="w-full pl-10 pr-4 py-3 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white placeholder-gray-500 focus:border-amber-500/60 focus:ring-1 focus:ring-amber-500/20 outline-none transition-colors min-h-[44px]"
            />
          </div>
          <div className="flex gap-2">
            <Button color="amber" onClick={() => setShowAdd((v) => !v)}>
              <Plus className="w-4 h-4 mr-2" /> Add
            </Button>
            <Button
              color="red"
              onClick={() => window.confirm('Clear ALL credentials?') && clearMutation.mutate()}
              loading={clearMutation.isPending}
            >
              <Trash2 className="w-4 h-4 mr-2" /> Clear
            </Button>
          </div>
        </div>

        {showAdd && (
          <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
            <input
              type="text"
              value={add.target}
              onChange={(e) => setAdd({ ...add, target: e.target.value })}
              placeholder="Target URL / host (optional)"
              className="px-3 py-2.5 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white placeholder-gray-500 focus:border-amber-500/60 focus:ring-1 focus:ring-amber-500/20 outline-none transition-colors min-h-[40px]"
            />
            <input
              type="text"
              value={add.username}
              onChange={(e) => setAdd({ ...add, username: e.target.value })}
              placeholder="Username"
              className="px-3 py-2.5 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white placeholder-gray-500 focus:border-amber-500/60 focus:ring-1 focus:ring-amber-500/20 outline-none transition-colors min-h-[40px]"
            />
            <input
              type="text"
              value={add.password}
              onChange={(e) => setAdd({ ...add, password: e.target.value })}
              placeholder="Password"
              className="px-3 py-2.5 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white placeholder-gray-500 focus:border-amber-500/60 focus:ring-1 focus:ring-amber-500/20 outline-none transition-colors min-h-[40px]"
            />
            <Button color="amber" onClick={() => add.username.trim() && addMutation.mutate()} loading={addMutation.isPending} disabled={!add.username.trim()}>
              Save to Vault
            </Button>
          </div>
        )}
      </Card>

      {toast && (
        <div className="fixed bottom-6 right-6 z-50 px-4 py-2 rounded-lg bg-gray-800 border border-gray-700 text-sm text-gray-200 shadow-lg">
          {toast}
        </div>
      )}

      {data?.creds.length === 0 ? (
        <EmptyState
          icon={<KeyRound className="w-12 h-12" />}
          title="No credentials stored"
          description="Found credentials from Brute Force, Password Spray, Cred Stuffing, and Account Enum are saved here automatically. You can also add entries manually."
        />
      ) : (
        <Card className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-gray-800 text-[10px] uppercase tracking-wider text-gray-600">
                <th className="px-3 py-3">Username</th>
                <th className="px-3 py-3">Password</th>
                <th className="px-3 py-3 hidden md:table-cell">Target</th>
                <th className="px-3 py-3">Source</th>
                <th className="px-3 py-3 hidden lg:table-cell">Added</th>
                <th className="px-3 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {data?.creds.map((c) => (
                <tr key={c.id} className="border-b border-gray-800/60 hover:bg-gray-800/30">
                  <td className="px-3 py-2.5">
                    <button onClick={() => copy(c.username)} className="text-sm text-gray-200 font-mono hover:text-amber-400 transition-colors" title="Copy username">
                      {c.username}
                    </button>
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="flex items-center gap-1.5">
                      <span className="text-sm text-gray-300 font-mono">
                        {revealed.has(c.id) ? c.password || '—' : '••••••••'}
                      </span>
                      <button onClick={() => toggleReveal(c.id)} className="p-1 text-gray-600 hover:text-white transition-colors" title="Reveal">
                        {revealed.has(c.id) ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                      {c.password && (
                        <button onClick={() => copy(c.password)} className="p-1 text-gray-600 hover:text-white transition-colors" title="Copy password">
                          <Copy className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </td>
                  <td className="px-3 py-2.5 hidden md:table-cell">
                    <span className="text-xs text-gray-500 font-mono break-all">{c.target || '—'}</span>
                  </td>
                  <td className="px-3 py-2.5">
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400">{c.source}</span>
                  </td>
                  <td className="px-3 py-2.5 hidden lg:table-cell text-xs text-gray-600">
                    {new Date(c.created_at * 1000).toLocaleString()}
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    <button
                      onClick={() => delMutation.mutate(c.id)}
                      className="p-1.5 text-gray-600 hover:text-red-400 transition-colors"
                      title="Delete"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  )
}
