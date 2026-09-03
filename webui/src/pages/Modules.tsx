import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Shield, Bug, Eye } from 'lucide-react'
import { useState } from 'react'
import clsx from 'clsx'
import api from '../api'
import { PageHeader, Spinner, SearchInput, EmptyState } from '../components/UI'
import { rankClass } from '../utils/colors'
import type { Module, ModuleListResponse } from '../types'

const typeIcons: Record<string, typeof Shield> = { exploit: Bug, auxiliary: Eye }

export default function Modules() {
  const [search, setSearch] = useState('')
  const [filterType, setFilterType] = useState<string>('all')

  const { data, isLoading } = useQuery({
    queryKey: ['modules'],
    queryFn: async () => { const res = await api.get<ModuleListResponse>('/modules'); return res.data.modules },
  })

  const modules = (data || []).filter((m) => {
    const matchesSearch = !search || m.name.toLowerCase().includes(search.toLowerCase()) || m.path.toLowerCase().includes(search.toLowerCase()) || (m.cve && m.cve.toLowerCase().includes(search.toLowerCase()))
    const matchesType = filterType === 'all' || m.type === filterType
    return matchesSearch && matchesType
  })

  return (
    <div className="space-y-4">
      <PageHeader title="Modules" subtitle={`${modules.length} available modules`} icon={<Shield className="w-8 h-8" />} color="green" />

      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1">
          <SearchInput value={search} onChange={setSearch} placeholder="Search modules, CVEs..." />
        </div>
        <div className="flex bg-gray-800/60 border border-gray-700/40 rounded-lg overflow-hidden">
          {['all', 'exploit', 'auxiliary'].map((t) => (
            <button
              key={t}
              onClick={() => setFilterType(t)}
              className={clsx(
                'px-4 py-2.5 min-h-[40px] text-xs font-medium capitalize transition-colors',
                filterType === t ? 'bg-webforge-500/15 text-webforge-400' : 'text-gray-500 hover:text-gray-300',
              )}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {isLoading ? (
        <Spinner text="Loading modules..." color="green" />
      ) : modules.length === 0 ? (
        <EmptyState
          icon={<Shield className="w-8 h-8" />}
          title="No modules found"
          description="Try adjusting your search or filter criteria."
        />
      ) : (
        <div className="space-y-1.5">
          {modules.map((m) => {
            const Icon = typeIcons[m.type] || Shield
            return (
              <Link
                key={m.path}
                to={`/modules/${encodeURIComponent(m.path)}`}
                className="block p-3 bg-gray-900/40 border border-gray-800/40 rounded-xl hover:border-gray-700/60 hover:bg-gray-800/30 transition-all group"
              >
                <div className="flex items-center gap-3">
                  <Icon className="w-4 h-4 text-gray-600 group-hover:text-webforge-400 transition-colors shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium text-gray-100 group-hover:text-webforge-300 transition-colors text-sm">{m.name}</span>
                      <span className={clsx('text-[10px] px-1.5 py-0.5 rounded font-medium', rankClass[m.rank] || rankClass.normal)}>{m.rank}</span>
                      {m.cve && <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 font-mono border border-red-500/20">{m.cve}</span>}
                      {m.cvss != null && <span className="text-[10px] text-yellow-400">CVSS {m.cvss}</span>}
                    </div>
                    <p className="text-xs text-gray-500 mt-0.5 line-clamp-2 sm:line-clamp-1">{m.description}</p>
                    <code className="text-[10px] text-gray-600 block font-mono truncate">{m.path}</code>
                  </div>
                </div>
              </Link>
            )
          })}
        </div>
      )}
    </div>
  )
}
