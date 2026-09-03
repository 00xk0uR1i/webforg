import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { Users, AtSign, Mail, Copy, ExternalLink, Filter, Search, ShieldAlert, Fingerprint, Database } from 'lucide-react'
import clsx from 'clsx'
import api from '../api'
import { PageHeader, Card, Button, Spinner, Stats, EmptyState, SectionHeader } from '../components/UI'
import { StatusBadge } from '../features/common/badges'
import { useCopy } from '../hooks/useCopy'
import type {
  OsintPlatformsResponse,
  OsintScanResponse,
  OsintResult,
  BreachResponse,
  BreachSourcesResponse,
} from '../types'

export default function AccountEnum() {
  const [mode, setMode] = useState<'username' | 'email'>('username')
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const [allSelected, setAllSelected] = useState(true)

  const { copy } = useCopy()

  const { data: platformsData } = useQuery({
    queryKey: ['osint-platforms'],
    queryFn: async () => {
      const res = await api.get<OsintPlatformsResponse>('/osint/platforms')
      return res.data
    },
  })

  const scanMutation = useMutation({
    mutationFn: async (payload: { query: string; mode: string; categories: string[] }) => {
      const res = await api.post<OsintScanResponse>('/osint/scan', {
        query: payload.query,
        mode: payload.mode,
        categories: payload.categories,
        workers: 16,
      })
      return res.data
    },
  })

  const [breachMode, setBreachMode] = useState<'email' | 'username'>('email')
  const [breachQuery, setBreachQuery] = useState('')
  const breachMutation = useMutation({
    mutationFn: async (payload: { query: string; mode: string }) => {
      const res = await api.post<BreachResponse>('/osint/breach', payload)
      return res.data
    },
  })
  const breach = breachMutation.data

  const { data: providersData } = useQuery({
    queryKey: ['osint-breach-sources'],
    queryFn: async () => {
      const res = await api.get<BreachSourcesResponse>('/osint/breach/sources')
      return res.data.providers
    },
  })

  const reg = mode === 'username' ? platformsData?.username : platformsData?.email
  const categories: string[] = reg?.categories || []
  const run = scanMutation.data

  const toggleCategory = (cat: string) => {
    setAllSelected(false)
    setSelected((prev) => (prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat]))
  }

  const handleScan = () => {
    if (!query.trim()) return
    scanMutation.mutate({ query: query.trim(), mode, categories: allSelected ? [] : selected })
  }

  const copyProfile = async (r: OsintResult) => {
    const lines = [`${r.name} (${r.platform}) — ${r.category}`, r.url]
    for (const [k, v] of Object.entries(r.profile)) lines.push(`${k}: ${v}`)
    await copy(lines.join('\n'))
  }

  const found = run?.results.filter((r) => r.status === 'found') || []
  const notFound = run?.results.filter((r) => r.status === 'not_found') || []
  const errors = run?.results.filter((r) => r.status === 'error') || []

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader
        title="Account Enumeration"
        subtitle="OSINT username & email existence scanner — check a handle across 49+ platforms (user-scanner style)"
        icon={<Users className="w-8 h-8" />}
        color="purple"
      >
        <div className="flex items-start gap-2 px-1">
          <Search className="w-4 h-4 text-gray-500 shrink-0 mt-0.5" />
          <p className="text-xs text-gray-500">Uses public profile pages and open APIs only. No logins, no private data.</p>
        </div>
      </PageHeader>

      {/* Controls */}
      <Card>
        <div className="flex flex-wrap gap-2 mb-4">
          <button
            onClick={() => { setMode('username'); setQuery(''); scanMutation.reset() }}
            className={clsx(
              'flex items-center gap-1.5 text-sm px-4 py-2.5 rounded-lg border transition-colors min-h-[44px]',
              mode === 'username'
                ? 'bg-purple-500/15 border-purple-500/40 text-purple-400'
                : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200',
            )}
          >
            <AtSign className="w-4 h-4" /> Username
          </button>
          <button
            onClick={() => { setMode('email'); setQuery(''); scanMutation.reset() }}
            className={clsx(
              'flex items-center gap-1.5 text-sm px-4 py-2.5 rounded-lg border transition-colors min-h-[44px]',
              mode === 'email'
                ? 'bg-purple-500/15 border-purple-500/40 text-purple-400'
                : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200',
            )}
          >
            <Mail className="w-4 h-4" /> Email
          </button>
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1 min-w-0">
            <AtSign className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              placeholder={mode === 'username' ? 'Username to scan... e.g. torvalds' : 'Email to scan... e.g. user@example.com'}
              className="w-full pl-10 pr-4 py-3 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white placeholder-gray-500 focus:border-purple-500/60 focus:ring-1 focus:ring-purple-500/20 outline-none transition-colors min-h-[44px]"
            />
          </div>
          <Button color="purple" onClick={handleScan} loading={scanMutation.isPending} disabled={!query.trim()}>
            <Search className="w-4 h-4 mr-2" /> {scanMutation.isPending ? 'Scanning...' : 'Scan'}
          </Button>
        </div>

        <div className="mt-4">
          <div className="flex items-center gap-2 mb-2">
            <Filter className="w-3.5 h-3.5 text-gray-500" />
            <div className="text-[10px] text-gray-500 uppercase tracking-wider">Categories — {reg?.count || 0} platforms</div>
            <button
              onClick={() => { setAllSelected(true); setSelected([]) }}
              className={`ml-auto text-[11px] px-2 py-1 rounded min-h-[28px] ${allSelected ? 'bg-purple-500/15 text-purple-400' : 'text-gray-500 hover:text-gray-300'}`}
            >
              All
            </button>
            <button
              onClick={() => { setAllSelected(false); setSelected([]) }}
              className="text-[11px] px-2 py-1 rounded text-gray-500 hover:text-gray-300 min-h-[28px]"
            >
              None
            </button>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {categories.map((c) => (
              <button
                key={c}
                onClick={() => toggleCategory(c)}
                className={clsx(
                  'text-xs px-3 py-2 rounded-lg border transition-colors min-h-[36px]',
                  allSelected || selected.includes(c)
                    ? 'bg-purple-500/15 border-purple-500/40 text-purple-400'
                    : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200',
                )}
              >
                {c}
              </button>
            ))}
          </div>
        </div>
      </Card>

      {/* Loading */}
      {scanMutation.isPending && (
        <Card>
          <Spinner text={`Scanning ${reg?.count || 0} platforms...`} color="purple" />
        </Card>
      )}

      {/* Results */}
      {run && !scanMutation.isPending && (
        <div className="space-y-4">
          <Stats stats={[
            { label: 'Platforms Checked', value: run.total || 0 },
            { label: 'Found', value: found.length, color: 'green' },
            { label: 'Not Found', value: notFound.length },
            { label: 'Errors', value: errors.length, color: errors.length > 0 ? 'red' : undefined },
          ]} />

          {found.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between px-1">
                <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  Found — {run.query} ({run.elapsed_ms}ms)
                </div>
              </div>
              {found.map((r) => (
                <Card key={r.platform}>
                  <div className="flex items-start gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-medium text-gray-100">{r.name}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-500">{r.category}</span>
                        <StatusBadge status="found" />
                      </div>
                      {r.url && (
                        <a href={r.url} target="_blank" rel="noopener noreferrer" className="text-[11px] text-purple-400 font-mono break-all hover:underline inline-flex items-center gap-1 mt-1">
                          <ExternalLink className="w-3 h-3" /> {r.url}
                        </a>
                      )}
                      {Object.keys(r.profile).length > 0 && (
                        <div className="flex flex-wrap gap-1.5 mt-2">
                          {Object.entries(r.profile).map(([k, v]) => (
                            <span key={k} className="text-[10px] px-2 py-1 rounded bg-gray-800/80 text-gray-400">
                              <span className="text-gray-600">{k}:</span> {String(v).slice(0, 40)}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                    <button
                      onClick={() => copyProfile(r)}
                      className="p-2 rounded-lg text-gray-500 hover:text-white hover:bg-gray-800 transition-colors min-w-[36px] min-h-[36px] flex items-center justify-center"
                      title="Copy profile info"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  </div>
                </Card>
              ))}
            </div>
          )}

          {(notFound.length > 0 || errors.length > 0) && (
            <div className="space-y-2">
              <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider px-1">Others</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-2">
                {[...notFound, ...errors].map((r) => (
                  <Card key={r.platform} className="flex items-center gap-3">
                    <StatusBadge status={r.status} className="shrink-0" />
                    <div className="min-w-0">
                      <div className="text-xs text-gray-300 truncate">{r.name}</div>
                      <div className="text-[10px] text-gray-600 truncate">{r.detail || r.category}</div>
                    </div>
                  </Card>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Initial state */}
      {!run && !scanMutation.isPending && (
        <EmptyState
          icon={<Users className="w-12 h-12" />}
          title="OSINT Account Scanner"
          description={`Enter a username or email to check where it's registered. Powered by a curated registry of ${reg?.count || 49}+ public platforms across Development, Social, Gaming, Streaming, and community sites.`}
          action={
            <div className="flex flex-wrap justify-center gap-2">
              {['torvalds', 'gandalf', 'sysadmin', '0xdeadbeef'].map((t) => (
                <button
                  key={t}
                  onClick={() => { setMode('username'); setQuery(t); scanMutation.mutate({ query: t, mode: 'username', categories: [] }) }}
                  className="text-xs px-3 py-1.5 rounded-lg bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700 transition-colors border border-gray-700 min-h-[36px]"
                >
                  {t}
                </button>
              ))}
            </div>
          }
        />
      )}

      {/* Data breach checker */}
      <Card>
        <div className="mb-3">
          <SectionHeader
            icon={<ShieldAlert className="w-4 h-4 text-red-400" />}
            title="Data Breach Checker"
            action={<span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-500">Multi-source</span>}
          />
        </div>
        <p className="text-xs text-gray-600 mb-3">
          Checks a <span className="text-gray-400">username</span> or <span className="text-gray-400">email</span> against leak and
          infostealer databases. Different sources cover different dumps — HaveIBeenPwned covers database breaches, Hudson Rock covers
          infostealer logs.
        </p>

        <div className="flex flex-wrap gap-1.5 mb-3">
          {(providersData || []).map((p) => (
            <span key={p.id} className={`text-[10px] px-2 py-1 rounded flex items-center gap-1.5 ${
              p.enabled ? 'bg-green-400/10 text-green-400' : 'bg-amber-400/10 text-amber-400'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${p.enabled ? 'bg-green-400' : 'bg-amber-400'}`} />
              {p.name}
              {!p.enabled && p.key_needed && (
                <span className="font-mono opacity-70">{p.key_needed}</span>
              )}
            </span>
          ))}
        </div>

        <div className="flex flex-wrap gap-2 mb-3">
          <button
            onClick={() => setBreachMode('email')}
            className={clsx(
              'flex items-center gap-1.5 text-sm px-4 py-2.5 rounded-lg border transition-colors min-h-[44px]',
              breachMode === 'email'
                ? 'bg-red-500/15 border-red-500/40 text-red-400'
                : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200',
            )}
          >
            <Mail className="w-4 h-4" /> Email
          </button>
          <button
            onClick={() => setBreachMode('username')}
            className={clsx(
              'flex items-center gap-1.5 text-sm px-4 py-2.5 rounded-lg border transition-colors min-h-[44px]',
              breachMode === 'username'
                ? 'bg-red-500/15 border-red-500/40 text-red-400'
                : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200',
            )}
          >
            <AtSign className="w-4 h-4" /> Username
          </button>
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1 min-w-0">
            <Database className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              value={breachQuery}
              onChange={(e) => setBreachQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && breachQuery.trim() && breachMutation.mutate({ query: breachQuery.trim(), mode: breachMode })}
              placeholder={breachMode === 'email' ? 'Email to check for exposure... e.g. user@example.com' : 'Username to check for exposure...'}
              className="w-full pl-10 pr-4 py-3 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white placeholder-gray-500 focus:border-red-500/60 focus:ring-1 focus:ring-red-500/20 outline-none transition-colors min-h-[44px]"
            />
          </div>
          <Button color="red" onClick={() => breachMutation.mutate({ query: breachQuery.trim(), mode: breachMode })} loading={breachMutation.isPending} disabled={!breachQuery.trim()}>
            <Search className="w-4 h-4 mr-2" /> {breachMutation.isPending ? 'Checking...' : 'Check'}
          </Button>
        </div>

        {breachMutation.isPending && (
          <div className="mt-3">
            <Spinner text={`Querying ${breachMode === 'email' ? 'email' : 'username'} against infostealer logs...`} color="red" />
          </div>
        )}

        {breach && !breachMutation.isPending && (
          <div className="mt-4 space-y-4">
            {!breach.success ? (
              <div className="text-xs text-red-400">{breach.error}</div>
            ) : (
              <>
                <div className={`flex items-start gap-2 rounded-lg border px-4 py-3 ${
                  breach.exposed ? 'bg-red-500/10 border-red-500/30' : 'bg-green-500/10 border-green-500/30'
                }`}>
                  {breach.exposed ? <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" /> : <ShieldAlert className="w-4 h-4 text-green-400 shrink-0 mt-0.5" />}
                  <div>
                    <div className={`text-sm font-medium ${breach.exposed ? 'text-red-400' : 'text-green-400'}`}>
                      {breach.exposed ? 'Exposure found' : 'No exposure found'}
                    </div>
                    <div className="text-[11px] text-gray-500 mt-0.5">{breach.message}</div>
                  </div>
                </div>

                {breach.sources.map((s) => (
                  <div key={s.id} className="space-y-2">
                    <div className="flex items-center gap-2 px-1">
                      <span className={`w-1.5 h-1.5 rounded-full ${s.exposed ? 'bg-red-400' : 'bg-green-400'}`} />
                      <span className="text-sm font-medium text-gray-300">{s.name}</span>
                      {s.exposed && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded font-bold bg-red-400/10 text-red-400">EXPOSED</span>
                      )}
                      {!s.exposed && s.enabled && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded font-bold bg-green-400/10 text-green-400">CLEAN</span>
                      )}
                      {!s.enabled && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-400/10 text-amber-400">NOT CONFIGURED</span>
                      )}
                    </div>

                    {s.error && (
                      <div className="text-[11px] text-amber-400 px-1">{s.error}</div>
                    )}

                    {s.id === 'hudson_rock' && s.enabled && s.stealers && (
                      <>
                        <Stats stats={[
                          { label: 'Infections', value: s.total_infections || 0, color: s.exposed ? 'red' : 'green' },
                          { label: 'Corporate Services', value: s.total_corporate_services || 0 },
                          { label: 'User Services', value: s.total_user_services || 0 },
                        ]} />
                        {s.stealers.length > 0 && (
                          <div className="space-y-2">
                            <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Infected computers ({s.total_infections})</div>
                            {s.stealers.map((st, i) => (
                              <Card key={i} className="space-y-2">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <Fingerprint className="w-3.5 h-3.5 text-red-400 shrink-0" />
                                  <span className="text-sm font-medium text-gray-100">{st.stealer_family || 'Info-stealer'}</span>
                                  {st.os && <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400">{st.os}</span>}
                                  {st.date_compromised && (
                                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-500">
                                      {new Date(st.date_compromised).toLocaleString()}
                                    </span>
                                  )}
                                </div>
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1 text-[11px] text-gray-500">
                                  {st.computer_name && st.computer_name !== 'Not Found' && <div><span className="text-gray-600">Computer:</span> {st.computer_name}</div>}
                                  {st.ip && <div><span className="text-gray-600">IP:</span> {st.ip}</div>}
                                  <div><span className="text-gray-600">Corporate services:</span> {st.corporate_services}</div>
                                  <div><span className="text-gray-600">User services:</span> {st.user_services}</div>
                                  {st.malware_path && st.malware_path !== 'Not Found' && (
                                    <div className="sm:col-span-2"><span className="text-gray-600">Malware path:</span> <span className="font-mono break-all">{st.malware_path}</span></div>
                                  )}
                                  {st.antiviruses.length > 0 && (
                                    <div className="sm:col-span-2"><span className="text-gray-600">Antiviruses:</span> {st.antiviruses.join(', ')}</div>
                                  )}
                                </div>
                                {(st.top_logins.length > 0 || st.top_passwords.length > 0) && (
                                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                    {st.top_logins.length > 0 && (
                                      <div className="bg-gray-950/60 border border-gray-800 rounded-lg p-2">
                                        <div className="text-[10px] text-gray-600 uppercase tracking-wider mb-1">Top logins (masked)</div>
                                        {st.top_logins.slice(0, 5).map((l, j) => (
                                          <div key={j} className="text-[11px] text-gray-400 font-mono truncate">{l || '—'}</div>
                                        ))}
                                      </div>
                                    )}
                                    {st.top_passwords.length > 0 && (
                                      <div className="bg-gray-950/60 border border-gray-800 rounded-lg p-2">
                                        <div className="text-[10px] text-gray-600 uppercase tracking-wider mb-1">Top passwords (masked)</div>
                                        {st.top_passwords.slice(0, 5).map((p, j) => (
                                          <div key={j} className="text-[11px] text-gray-400 font-mono truncate">{p || '—'}</div>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                )}
                              </Card>
                            ))}
                          </div>
                        )}
                      </>
                    )}

                    {s.id === 'hibp' && s.enabled && (
                      <>
                        {s.breaches && s.breaches.length > 0 ? (
                          <div className="space-y-2">
                            {s.breaches.map((b, i) => (
                              <Card key={i} className="space-y-2">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <Database className="w-3.5 h-3.5 text-red-400 shrink-0" />
                                  <span className="text-sm font-medium text-gray-100">{b.title || b.name}</span>
                                  {b.verified && <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-400/10 text-green-400">VERIFIED</span>}
                                  {b.sensitive && <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-400/10 text-red-400">SENSITIVE</span>}
                                </div>
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1 text-[11px] text-gray-500">
                                  {b.domain && <div><span className="text-gray-600">Domain:</span> {b.domain}</div>}
                                  {b.breach_date && <div><span className="text-gray-600">Breach date:</span> {b.breach_date}</div>}
                                  {typeof b.pwn_count === 'number' && <div><span className="text-gray-600">Pwned accounts:</span> {b.pwn_count.toLocaleString()}</div>}
                                  {b.data_classes && b.data_classes.length > 0 && (
                                    <div className="sm:col-span-2">
                                      <span className="text-gray-600">Data:</span>{' '}
                                      {b.data_classes.map((dc) => (
                                        <span key={dc} className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 mr-1">{dc}</span>
                                      ))}
                                    </div>
                                  )}
                                  {b.description && (
                                    <div className="sm:col-span-2 text-gray-400 leading-relaxed">{b.description.slice(0, 400)}</div>
                                  )}
                                </div>
                              </Card>
                            ))}
                          </div>
                        ) : (
                          <div className="text-[11px] text-gray-600 px-1">No known breaches in the HaveIBeenPwned database.</div>
                        )}
                      </>
                    )}

                    {s.id === 'emailrep' && s.enabled && (
                      <div className="space-y-2">
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                          <Card className="text-center">
                            <div className={`text-lg font-bold ${s.leaked ? 'text-red-400' : 'text-green-400'}`}>{s.leaked ? 'Yes' : 'No'}</div>
                            <div className="text-[10px] text-gray-600 uppercase tracking-wider mt-1">Credentials leaked</div>
                          </Card>
                          <Card className="text-center">
                            <div className="text-lg font-bold text-gray-300">{s.reputation ?? '—'}</div>
                            <div className="text-[10px] text-gray-600 uppercase tracking-wider mt-1">Reputation</div>
                          </Card>
                          <Card className="text-center">
                            <div className={`text-lg font-bold ${s.suspicious ? 'text-red-400' : 'text-green-400'}`}>{s.suspicious ? 'Yes' : 'No'}</div>
                            <div className="text-[10px] text-gray-600 uppercase tracking-wider mt-1">Suspicious</div>
                          </Card>
                          <Card className="text-center">
                            <div className="text-lg font-bold text-gray-300">{s.profiles ?? 0}</div>
                            <div className="text-[10px] text-gray-600 uppercase tracking-wider mt-1">Profiles</div>
                          </Card>
                        </div>
                        {s.breaches && s.breaches.length > 0 && (
                          <div className="space-y-1.5">
                            <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Breach hits</div>
                            {s.breaches.map((b, i) => (
                              <div key={i} className="flex items-center justify-between bg-gray-950/60 border border-gray-800 rounded-lg px-3 py-2">
                                <span className="text-xs text-gray-300">{b.name}</span>
                                {b.date && <span className="text-[11px] text-gray-600">{b.date}</span>}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </>
            )}
          </div>
        )}
      </Card>
    </div>
  )
}
