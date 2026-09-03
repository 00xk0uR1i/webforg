import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { Search, Copy, Check, ExternalLink, Globe, FolderOpen, Shield, Link2 } from 'lucide-react'
import api from '../api'
import { PageHeader, Card, Button, Spinner } from '../components/UI'
import { useCopy } from '../hooks/useCopy'
import type { Dork, DorkCategory, DorkLibraryResponse, DorkRunResponse } from '../types'

const engineMeta: Record<string, { label: string; badge: string }> = {
  ddg: { label: 'DuckDuckGo', badge: 'bg-cyan-400/10 text-cyan-400' },
  bing: { label: 'Bing', badge: 'bg-blue-400/10 text-blue-400' },
  brave: { label: 'Brave', badge: 'bg-orange-400/10 text-orange-400' },
  google_cse: { label: 'Google CSE', badge: 'bg-green-400/10 text-green-400' },
}

const AVAILABLE_ENGINES = [
  { id: 'ddg', label: 'DuckDuckGo' },
  { id: 'bing', label: 'Bing' },
  { id: 'brave', label: 'Brave' },
  { id: 'google_cse', label: 'Google CSE' },
]

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, '')
  } catch {
    return url
  }
}

export default function Dorking() {
  const [query, setQuery] = useState('')
  const [target, setTarget] = useState('')
  const [engines, setEngines] = useState<string[]>(['ddg', 'bing'])
  const [activeCategory, setActiveCategory] = useState<string | null>(null)
  const { copy, copied } = useCopy(2000)

  const { data: libraryData } = useQuery({
    queryKey: ['dork-library'],
    queryFn: async () => {
      const res = await api.get<DorkLibraryResponse>('/dork/library')
      return res.data.categories
    },
  })

  const runMutation = useMutation({
    mutationFn: async (payload: { query: string; target: string; engines: string[] }) => {
      const res = await api.post<DorkRunResponse>('/dork/run', {
        query: payload.query,
        target: payload.target || null,
        engines: payload.engines,
        limit: 30,
      })
      return res.data
    },
  })

  const categories: DorkCategory[] = libraryData || []
  const activeCat = categories.find((c) => c.category === activeCategory) || categories[0]
  const run = runMutation.data

  const handleRun = (q?: string, t?: string) => {
    const queryToRun = (q ?? query).trim()
    const targetToRun = (t ?? target).trim()
    if (!queryToRun) return
    runMutation.mutate({ query: queryToRun, target: targetToRun, engines })
  }

  const applyDork = (dork: Dork) => {
    setQuery(dork.query)
    setActiveCategory(activeCat?.category ?? null)
    if (dork.query.includes('{target}')) {
      handleRun(dork.query, target)
    } else {
      setQuery(dork.query)
    }
  }

  const copyUrl = async (url: string) => {
    await copy(url, url)
  }

  const toggleEngine = (id: string) => {
    setEngines((prev) => (prev.includes(id) ? prev.filter((e) => e !== id) : [...prev, id]))
  }

  const okEngines = run ? Object.values(run.engines).filter((e) => e.status === 'ok').length : 0

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader
        title="Dorking"
        subtitle="Discover websites and exposed assets with Google-style search dorks across multiple engines"
        icon={<Globe className="w-8 h-8" />}
        color="cyan"
      />

      {/* Query controls */}
      <Card>
        <div className="flex flex-col lg:flex-row gap-3">
          <div className="flex-1 min-w-0 space-y-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                type="text"
                placeholder={'Dork query... e.g. intitle:"index of" / or filetype:sql "INSERT INTO"'}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleRun()}
                className="w-full pl-10 pr-4 py-3 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white placeholder-gray-500 focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors min-h-[44px]"
              />
            </div>
            <div className="relative">
              <Link2 className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                type="text"
                placeholder="Target domain (optional) — scopes results with site:target"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleRun()}
                className="w-full pl-10 pr-4 py-3 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white placeholder-gray-500 focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors min-h-[44px]"
              />
            </div>
          </div>
          <div className="flex items-end gap-2">
            <div className="flex flex-col gap-2">
              <div className="text-[10px] text-gray-500 uppercase tracking-wider">Engines</div>
              <div className="flex flex-wrap gap-1.5">
                {AVAILABLE_ENGINES.map((e) => {
                  const on = engines.includes(e.id)
                  return (
                    <button
                      key={e.id}
                      onClick={() => toggleEngine(e.id)}
                      className={`text-xs px-3 py-2 rounded-lg border transition-colors min-h-[36px] ${
                        on
                          ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-400'
                          : 'bg-gray-800 border-gray-700 text-gray-500 hover:text-gray-300'
                      }`}
                      title={e.label}
                    >
                      {e.label}
                    </button>
                  )
                })}
              </div>
            </div>
            <Button color="cyan" onClick={() => handleRun()} loading={runMutation.isPending} className="lg:h-[52px] whitespace-nowrap">
              <Search className="w-4 h-4 mr-2" /> {runMutation.isPending ? 'Searching...' : 'Run Dork'}
            </Button>
          </div>
        </div>
      </Card>

      {/* Dork library */}
      <Card>
        <div className="flex items-center justify-between mb-3">
          <div className="text-[10px] text-gray-500 uppercase tracking-wider">Dork Library</div>
          <div className="text-[10px] text-gray-600">Click a dork to load it</div>
        </div>
        <div className="flex flex-wrap gap-1.5 mb-3">
          {categories.map((c) => (
            <button
              key={c.category}
              onClick={() => setActiveCategory(c.category)}
              className={`text-xs px-3 py-2 rounded-lg border transition-colors min-h-[36px] ${
                activeCat?.category === c.category
                  ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-400'
                  : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'
              }`}
            >
              {c.category}
            </button>
          ))}
        </div>
        {activeCat && (
          <div className="flex flex-wrap gap-2">
            {activeCat.dorks.map((d) => (
              <button
                key={d.name}
                onClick={() => {
                  setQuery(d.query)
                  if (d.query.includes('{target}')) handleRun(d.query, target)
                }}
                className="text-xs px-3 py-2 rounded-lg bg-gray-800/60 border border-gray-700/60 text-gray-300 hover:border-cyan-500/40 hover:text-white transition-colors text-left min-h-[36px]"
                title={d.query}
              >
                {d.name}
              </button>
            ))}
          </div>
        )}
      </Card>

      {/* Results */}
      {runMutation.isPending && (
        <Card>
          <Spinner text="Searching engines..." color="cyan" />
        </Card>
      )}

      {runMutation.isError && (
        <Card className="text-center py-10">
          <div className="text-sm text-red-400">Search failed</div>
          <div className="text-xs text-gray-500 mt-1">Check your connection and try again</div>
        </Card>
      )}

      {run && run.total === 0 && !runMutation.isPending && (
        <Card className="text-center py-10">
          <Shield className="w-10 h-10 mx-auto mb-3 text-gray-600" />
          <div className="text-sm text-gray-400">No results found for this dork</div>
          <div className="text-xs text-gray-600 mt-1">Search engines may block some dork syntax — try another engine or dork</div>
        </Card>
      )}

      {run && run.total > 0 && !runMutation.isPending && (
        <div className="space-y-2">
          <div className="flex items-center justify-between px-1 flex-wrap gap-2">
            <div className="text-xs text-gray-500">
              {run.total} result{run.total === 1 ? '' : 's'} for <span className="text-cyan-400">{run.query}</span>
              {run.target && <span className="text-gray-400"> (scoped to {run.target})</span>}
              {' '}· {run.elapsed_ms}ms
            </div>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(run.engines).map(([id, st]) => (
                <span
                  key={id}
                  className={`text-[10px] px-2 py-1 rounded ${
                    st.status === 'ok'
                      ? engineMeta[id]?.badge || 'bg-gray-400/10 text-gray-400'
                      : 'bg-red-400/10 text-red-400'
                  }`}
                  title={st.message}
                >
                  {engineMeta[id]?.label || id}: {st.status === 'ok' ? `${st.count} hits` : 'blocked'}
                </span>
              ))}
            </div>
          </div>

          <div className="text-[10px] text-gray-600 px-1">
            {okEngines}/{Object.keys(run.engines).length} engines responded
          </div>

          {run.results.map((r) => (
            <Card key={r.url}>
              <div className="flex items-start gap-3">
                <div className="flex-1 min-w-0">
                  <a
                    href={r.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-gray-100 hover:text-cyan-400 font-medium break-all transition-colors"
                  >
                    {r.title || r.url}
                  </a>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${engineMeta[r.engine]?.badge || 'bg-gray-400/10 text-gray-400'}`}>
                      {engineMeta[r.engine]?.label || r.engine}
                    </span>
                    <span className="text-[11px] text-gray-500 font-mono break-all">{hostOf(r.url)}</span>
                  </div>
                  {r.snippet && (
                    <p className="text-xs text-gray-400 leading-relaxed mt-1.5 break-all">{r.snippet}</p>
                  )}
                </div>
                <div className="flex flex-col gap-2 shrink-0">
                  <button
                    onClick={() => copyUrl(r.url)}
                    className="p-2 rounded-lg text-gray-500 hover:text-white hover:bg-gray-800 transition-colors min-w-[36px] min-h-[36px] flex items-center justify-center"
                    title="Copy URL"
                  >
                    {copied === r.url ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                  </button>
                  <a
                    href={r.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-2 rounded-lg text-gray-500 hover:text-cyan-400 hover:bg-gray-800 transition-colors min-w-[36px] min-h-[36px] flex items-center justify-center"
                    title="Open"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </a>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Initial state */}
      {!run && !runMutation.isPending && (
        <Card className="text-center py-12">
          <FolderOpen className="w-12 h-12 mx-auto mb-3 text-gray-700" />
          <div className="text-sm text-gray-400 font-medium">Search the Web with Dorks</div>
          <div className="text-xs text-gray-600 mt-2 max-w-lg mx-auto">
            Pick a dork from the library, enter a query, or scope to a target domain. Results stream in from
            multiple search engines and are deduplicated. Safe dorks only — keep it legal.
          </div>
          <div className="flex flex-wrap justify-center gap-2 mt-4">
            {['intitle:"index of" /', 'inurl:admin intitle:login', 'filetype:sql "INSERT INTO"', 'intitle:phpinfo PHP Version'].map((term) => (
              <button
                key={term}
                onClick={() => { setQuery(term); handleRun(term) }}
                className="text-xs px-3 py-1.5 rounded-lg bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700 transition-colors border border-gray-700 min-h-[36px]"
              >
                {term}
              </button>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
