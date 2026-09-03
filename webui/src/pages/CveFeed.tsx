import { useMutation } from '@tanstack/react-query'
import { useState } from 'react'
import { Search, RefreshCw, Shield, Bug, ExternalLink, Code } from 'lucide-react'
import clsx from 'clsx'
import api from '../api'
import { PageHeader, Card, Button, Stats, Spinner, SearchInput, EmptyState } from '../components/UI'
import { SeverityBadge } from '../features/common/badges'
import { useApiQuery } from '../hooks/useApiQuery'
import type {
  CveEntry,
  SploitusExploit,
  CveSearchResponse,
  SploitusSearchResponse,
  SploitusStats,
} from '../types'

export default function CveFeed() {
  const [query, setQuery] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [tab, setTab] = useState<'cves' | 'exploits'>('cves')
  const [selectedExploit, setSelectedExploit] = useState<SploitusExploit | null>(null)

  const { data: cveData, isLoading: cveLoading } = useApiQuery<CveEntry[]>(
    ['cve', searchTerm],
    () => api.post<CveSearchResponse>('/cve/search', { query: searchTerm || '', min_cvss: 0, limit: 50 }).then((res) => res.data.cves),
    { enabled: tab === 'cves' },
  )

  const { data: exploitData, isLoading: exploitLoading } = useApiQuery<SploitusExploit[]>(
    ['sploitus', searchTerm],
    () => api.post<SploitusSearchResponse>('/sploitus/search', { query: searchTerm || '', min_cvss: 0, limit: 50 }).then((res) => res.data.exploits),
    { enabled: tab === 'exploits' },
  )

  const { data: stats } = useApiQuery<SploitusStats>(
    ['sploitus-stats'],
    () => api.get<SploitusStats>('/sploitus/stats').then((res) => res.data),
  )

  const updateMutation = useMutation({
    mutationFn: async () => { await api.post('/cve/update', { sploitus_pages: 5, nvd_days: 90 }) },
  })

  const handleSearch = () => setSearchTerm(query)
  const cves: CveEntry[] = cveData || []
  const exploits: SploitusExploit[] = exploitData || []
  const isLoading = tab === 'cves' ? cveLoading : exploitLoading

  return (
    <div className="space-y-4 sm:space-y-5">
      <PageHeader title="CVE Feed & Exploits" subtitle="Search CVE database and exploit repository" icon={<Shield className="w-8 h-8" />} color="green">
        {stats && (
          <Stats stats={[
            { label: 'Exploits', value: stats.total_exploits || 0, color: 'green' },
            { label: 'Unique CVEs', value: stats.unique_cves || 0, color: 'yellow' },
            { label: 'Last Fetch', value: stats.last_fetch ? new Date(stats.last_fetch).toLocaleDateString() : 'Never' },
          ]} />
        )}
      </PageHeader>

      <div className="flex items-center justify-between gap-3">
        <div className="flex gap-1 border-b border-gray-800/60 -mb-px">
          <button
            onClick={() => setTab('cves')}
            className={clsx(
              'flex items-center gap-2 px-3 py-2.5 text-sm font-medium border-b-2 transition-colors',
              tab === 'cves'
                ? 'border-webforge-500 text-webforge-400'
                : 'border-transparent text-gray-500 hover:text-gray-300',
            )}
          >
            <Shield className="w-4 h-4" /> CVEs
          </button>
          <button
            onClick={() => setTab('exploits')}
            className={clsx(
              'flex items-center gap-2 px-3 py-2.5 text-sm font-medium border-b-2 transition-colors',
              tab === 'exploits'
                ? 'border-red-500 text-red-400'
                : 'border-transparent text-gray-500 hover:text-gray-300',
            )}
          >
            <Bug className="w-4 h-4" /> Exploits
          </button>
        </div>
        <button
          onClick={() => updateMutation.mutate()}
          disabled={updateMutation.isPending}
          className="flex items-center gap-2 px-3 py-2 min-h-[40px] bg-gray-800/60 border border-gray-700/40 rounded-lg text-sm text-gray-400 hover:text-gray-200 hover:border-gray-600 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={clsx('w-4 h-4', updateMutation.isPending && 'animate-spin')} />
          <span className="hidden sm:inline">{updateMutation.isPending ? 'Updating...' : 'Update DB'}</span>
        </button>
      </div>

      <div className="flex flex-col sm:flex-row gap-2">
        <div className="flex-1 min-w-0">
          <SearchInput
            value={query}
            onChange={setQuery}
            placeholder={tab === 'cves' ? 'Search CVEs...' : 'Search exploits...'}
            onSearch={handleSearch}
          />
        </div>
        <Button onClick={handleSearch} className="w-full sm:w-auto shrink-0">Search</Button>
      </div>

      {isLoading ? (
        <Spinner text="Loading..." color="green" />
      ) : tab === 'cves' ? (
        cves.length === 0 ? (
          <EmptyState
            icon={<Shield className="w-8 h-8" />}
            title="No CVEs found"
            description="Try updating the database or adjusting your search."
          />
        ) : (
          <div className="space-y-2">
            {cves.map((cve) => (
              <Card key={cve.id} className="hover:border-gray-700/60 transition-colors">
                <div className="flex items-start gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noopener noreferrer" className="font-mono text-sm font-medium text-webforge-400 hover:text-webforge-300 flex items-center gap-1 transition-colors">
                        {cve.id} <ExternalLink className="w-3 h-3" />
                      </a>
                      {cve.severity && <SeverityBadge severity={cve.severity} variant="plain" />}
                      {cve.cvss != null && <span className="text-xs text-yellow-400">CVSS {cve.cvss}</span>}
                      {cve.cisa_kev && <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 font-medium border border-red-500/20">CISA KEV</span>}
                      {cve.exploit_available && <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 font-medium border border-purple-500/20">Has Exploit</span>}
                    </div>
                    <p className="text-sm text-gray-400 mt-2 line-clamp-2 leading-relaxed">{cve.description}</p>
                    <div className="flex items-center gap-3 mt-2 text-xs text-gray-600">
                      {cve.vendor && <span>Vendor: {cve.vendor}</span>}
                      {cve.product && <span>Product: {cve.product}</span>}
                      {cve.published && <span>Published: {cve.published.split('T')[0]}</span>}
                    </div>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )
      ) : exploits.length === 0 ? (
        <EmptyState
          icon={<Bug className="w-8 h-8" />}
          title="No exploits found"
          description="Try updating the database or adjusting your search."
        />
      ) : (
        <div className="space-y-2">
          {exploits.map((exp) => (
            <Card key={exp.id} className="hover:border-gray-700/60 transition-colors cursor-pointer" onClick={() => setSelectedExploit(selectedExploit?.id === exp.id ? null : exp)}>
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    {exp.cve_id && <span className="font-mono text-sm font-medium text-red-400">{exp.cve_id}</span>}
                    <span className="text-sm text-gray-300 truncate">{exp.title}</span>
                    {exp.cvss != null && <span className="text-xs text-yellow-400">CVSS {exp.cvss}</span>}
                    {exp.type && <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800/60 border border-gray-700/40 text-gray-400">{exp.type}</span>}
                  </div>
                  {exp.description && <p className="text-xs text-gray-500 mt-1 line-clamp-1">{exp.description}</p>}
                  {exp.source_url && (
                    <a href={exp.source_url} target="_blank" rel="noopener noreferrer" className="text-[11px] text-gray-600 hover:text-gray-400 mt-1 inline-flex items-center gap-1 transition-colors" onClick={(e) => e.stopPropagation()}>
                      {exp.source_url} <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>
                <Code className="w-4 h-4 text-gray-700 shrink-0" />
              </div>
              {selectedExploit?.id === exp.id && exp.code && (
                <div className="mt-4 output-block max-h-80">
                  <div className="text-xs text-gray-500 mb-2 font-mono">Source Code:</div>
                  <pre className="text-xs text-gray-300 whitespace-pre-wrap font-mono leading-relaxed break-all">{exp.code}</pre>
                </div>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
