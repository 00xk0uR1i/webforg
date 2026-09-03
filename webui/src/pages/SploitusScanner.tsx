import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Search, RefreshCw, Bug, ExternalLink, Code, Shield, ChevronDown, ChevronRight, Copy, Check } from 'lucide-react'
import clsx from 'clsx'
import api from '../api'
import { PageHeader, Card, Button, Stats, Spinner, EmptyState, OutputBlock } from '../components/UI'
import { useApiQuery } from '../hooks/useApiQuery'
import { useCopy } from '../hooks/useCopy'
import { exploitTypeClass } from '../utils/colors'
import type { SploitusExploit as Exploit, SploitusExploitDetail as ExploitDetail, SploitusSearchResponse, SploitusStats } from '../types'

export default function SploitusScanner() {
  const [query, setQuery] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedExploit, setSelectedExploit] = useState<string | null>(null)
  const { copy, copied } = useCopy()

  const { data: stats } = useApiQuery<SploitusStats>(
    ['sploitus-stats'],
    () => api.get<SploitusStats>('/sploitus/stats').then((res) => res.data),
  )

  const { data: exploitData, isLoading } = useApiQuery<Exploit[]>(
    ['sploitus-search', searchTerm],
    () => api.post<SploitusSearchResponse>('/sploitus/search', { query: searchTerm, min_cvss: 0, limit: 50 }).then((res) => res.data.exploits),
    { enabled: !!searchTerm },
  )

  const detailMutation = useMutation({
    mutationFn: async (exploitId: string) => {
      const res = await api.post<ExploitDetail>(`/sploitus/exploit/${exploitId}`)
      return res.data
    },
  })

  const updateMutation = useMutation({
    mutationFn: async () => {
      await api.post('/cve/update', { sploitus_pages: 5, nvd_days: 90 })
    },
  })

  const handleSearch = () => {
    if (query.trim()) setSearchTerm(query.trim())
  }

  const handleExploitClick = (exploit: Exploit) => {
    if (selectedExploit === exploit.id) {
      setSelectedExploit(null)
      return
    }
    setSelectedExploit(exploit.id)
    if (!detailMutation.data || detailMutation.data.id !== exploit.id) {
      detailMutation.mutate(exploit.id)
    }
  }

  const copyCode = (code: string) => {
    copy(code)
  }

  const exploits: Exploit[] = exploitData || []
  const detail = detailMutation.data

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader
        title="Sploitus Scanner"
        subtitle="Search the Sploitus exploit database for CVEs, PoCs, and attack code"
        icon={<Bug className="w-8 h-8" />}
        color="red"
      >
        {stats && (
          <Stats stats={[
            { label: 'Total Exploits', value: stats.total_exploits || 0, color: 'red' },
            { label: 'Unique CVEs', value: stats.unique_cves || 0, color: 'yellow' },
            { label: 'Last Fetch', value: stats.last_fetch ? new Date(stats.last_fetch).toLocaleDateString() : 'Never', color: 'green' },
          ]} />
        )}
      </PageHeader>

      {/* Search + Update */}
      <Card>
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1 min-w-0">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search CVEs, technologies, exploits... (e.g. CVE-2024-39397, WordPress, Apache)"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              className="w-full pl-10 pr-4 py-3 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white placeholder-gray-500 focus:border-red-500/60 focus:ring-1 focus:ring-red-500/20 outline-none transition-colors min-h-[44px]"
            />
          </div>
          <div className="flex gap-2">
            <Button onClick={handleSearch} className="flex-1 sm:flex-none min-h-[44px]">
              <Search className="w-4 h-4 mr-2" /> Search
            </Button>
            <button
              onClick={() => updateMutation.mutate()}
              disabled={updateMutation.isPending}
              className="flex items-center gap-2 px-4 py-2.5 min-h-[44px] bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-gray-300 hover:border-red-600/50 hover:text-white transition-colors disabled:opacity-50"
              title="Update exploit database from Sploitus RSS"
            >
              <RefreshCw className={`w-4 h-4 ${updateMutation.isPending ? 'animate-spin' : ''}`} />
              <span className="hidden sm:inline">{updateMutation.isPending ? 'Updating...' : 'Update DB'}</span>
            </button>
          </div>
        </div>
        {updateMutation.isSuccess && (
          <div className="mt-2 text-xs text-green-400">Database updated successfully</div>
        )}
      </Card>

      {/* Loading */}
      {isLoading && (
        <Card>
          <Spinner text="Searching Sploitus database..." color="red" />
        </Card>
      )}

      {/* No results */}
      {!isLoading && searchTerm && exploits.length === 0 && (
        <EmptyState
          icon={<Bug className="w-10 h-10" />}
          title={`No exploits found for "${searchTerm}"`}
          description="Try different keywords or update the database"
        />
      )}

      {/* Results */}
      {!isLoading && exploits.length > 0 && (
        <div className="space-y-2">
          <div className="text-xs text-gray-500 px-1">{exploits.length} exploits found</div>
          {exploits.map((exploit) => {
            const isOpen = selectedExploit === exploit.id
            const cvss = exploit.cvss || 0
            const cvssColor = cvss >= 9 ? 'text-red-400' : cvss >= 7 ? 'text-orange-400' : cvss >= 4 ? 'text-yellow-400' : 'text-gray-400'
            const typeClass = exploitTypeClass[exploit.type] || exploitTypeClass.unknown

            return (
              <Card key={exploit.id} className={clsx('transition-all', isOpen ? 'border-red-600/30' : 'hover:border-gray-700/50')}>
                {/* Exploit header */}
                <button
                  onClick={() => handleExploitClick(exploit)}
                  className="w-full text-left min-h-[44px]"
                >
                  <div className="flex items-center gap-3">
                    <div className={`w-10 text-center font-mono text-sm font-bold shrink-0 ${cvssColor}`}>
                      {cvss > 0 ? cvss.toFixed(1) : '—'}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        {exploit.cve_id && (
                          <span className="font-mono text-sm font-medium text-red-400">{exploit.cve_id}</span>
                        )}
                        <span className="text-sm text-gray-200 truncate">{exploit.title}</span>
                      </div>
                      <div className="flex items-center gap-2 mt-1 flex-wrap">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${typeClass}`}>
                          {exploit.type}
                        </span>
                        {exploit.published && (
                          <span className="text-[10px] text-gray-600">{exploit.published}</span>
                        )}
                      </div>
                    </div>
                    {isOpen ? (
                      <ChevronDown className="w-4 h-4 text-gray-500 shrink-0" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-gray-600 shrink-0" />
                    )}
                  </div>
                </button>

                {/* Expanded detail */}
                {isOpen && (
                  <div className="mt-4 space-y-3 border-t border-gray-800 pt-4">
                    {/* Description */}
                    {(detail?.description || exploit.description) && (
                      <div>
                        <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Description</div>
                        <p className="text-xs text-gray-400 leading-relaxed">
                          {detail?.description || exploit.description}
                        </p>
                      </div>
                    )}

                    {/* Source link */}
                    {exploit.source_url && (
                      <a
                        href={exploit.source_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 text-xs text-gray-500 hover:text-red-400 transition-colors min-h-[44px]"
                      >
                        <ExternalLink className="w-3 h-3" />
                        View on Sploitus
                      </a>
                    )}

                    {/* Source code */}
                    {(detail?.raw_code || exploit.code) && (
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-1">
                            <Code className="w-3 h-3" /> Source Code
                          </div>
                          <button
                            onClick={() => copyCode(detail?.raw_code || exploit.code)}
                            className="flex items-center gap-1 text-[10px] text-gray-500 hover:text-gray-300 min-h-[44px] px-2"
                          >
                            {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                            {copied ? 'Copied' : 'Copy'}
                          </button>
                        </div>
                        <OutputBlock maxHeight="max-h-64">
                          {detail?.raw_code || exploit.code}
                        </OutputBlock>
                      </div>
                    )}

                    {/* Loading detail */}
                    {detailMutation.isPending && detailMutation.variables === exploit.id && (
                      <div className="flex items-center gap-2 text-xs text-gray-500">
                        <div className="w-3 h-3 border border-gray-600 border-t-gray-400 rounded-full animate-spin" />
                        Loading full exploit details...
                      </div>
                    )}
                  </div>
                )}
              </Card>
            )
          })}
        </div>
      )}

      {/* Initial state */}
      {!searchTerm && !isLoading && (
        <EmptyState
          icon={<Bug className="w-12 h-12" />}
          title="Search Sploitus Exploits"
          description="Search by CVE ID, technology name, or keyword to find exploits, PoCs, and attack code from the Sploitus database."
          action={
            <div className="flex flex-wrap justify-center gap-2">
              {['CVE-2024-39397', 'WordPress', 'Apache Struts', 'Fortinet', 'jQuery'].map((term) => (
                <button
                  key={term}
                  onClick={() => { setQuery(term); setSearchTerm(term) }}
                  className="text-xs px-3 py-1.5 rounded-lg bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700 transition-colors border border-gray-700 min-h-[36px]"
                >
                  {term}
                </button>
              ))}
            </div>
          }
        />
      )}
    </div>
  )
}
