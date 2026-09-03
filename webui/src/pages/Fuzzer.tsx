import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Crosshair, Bug, Globe, AlertTriangle, FolderOpen, FileSearch, CheckCircle } from 'lucide-react'
import clsx from 'clsx'
import api from '../api'
import { PageHeader, Card, Input, Button, Stats, Table, Spinner, EmptyState, SectionHeader, OutputBlock } from '../components/UI'
import { getErrorMessage } from '../utils/error'
import type { FuzzFinding, FuzzResult } from '../types'

export default function Fuzzer() {
  const [target, setTarget] = useState('')
  const [showOptions, setShowOptions] = useState(false)
  const [threads, setThreads] = useState(10)
  const [timeout, setTimeout] = useState(8)
  const [maxDirs, setMaxDirs] = useState(200)
  const [maxCrawl, setMaxCrawl] = useState(25)
  const [maxParamTests, setMaxParamTests] = useState(150)
  const [wordlist, setWordlist] = useState('')
  const [extensions, setExtensions] = useState('')
  const [maxDepth, setMaxDepth] = useState(0)
  const [extraHeaders, setExtraHeaders] = useState('')
  const [toggles, setToggles] = useState({
    fuzz_dirs: true,
    spider: true,
    test_rce: true,
    test_xss: true,
    waf_bypass: false,
  })

  const runMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post<FuzzResult>('/fuzz/run', {
        target: target.trim(),
        threads,
        timeout,
        fuzz_dirs: toggles.fuzz_dirs,
        wordlist: wordlist.trim(),
        max_dirs: maxDirs,
        spider: toggles.spider,
        max_crawl: maxCrawl,
        test_rce: toggles.test_rce,
        test_xss: toggles.test_xss,
        max_param_tests: maxParamTests,
        extensions: extensions.trim(),
        max_depth: maxDepth,
        extra_headers: extraHeaders.trim(),
        waf_bypass: toggles.waf_bypass,
      })
      return res.data
    },
  })

  const toggle = (key: keyof typeof toggles) => {
    setToggles((p) => ({ ...p, [key]: !p[key] }))
  }

  const rce = (runMutation.data?.findings || []).filter((f) => f.type === 'rce')
  const xss = (runMutation.data?.findings || []).filter((f) => f.type === 'xss')
  const errStatus: number | undefined = (runMutation.error as { response?: { status?: number } } | null)?.response?.status

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader
        title="WebFuzzer"
        subtitle="Directory fuzzing + parameter spider. Discovers hidden paths, endpoints, and parameters, then tests every parameter for command injection (RCE) and reflected XSS."
        icon={<Crosshair className="w-8 h-8" />}
        color="amber"
      >
        <Card>
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row gap-2">
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && target.trim() && runMutation.mutate()}
                placeholder="https://target.com"
                className="flex-1 min-w-0 bg-gray-800/80 border border-gray-700/60 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:border-amber-500/60 focus:ring-1 focus:ring-amber-500/20 outline-none transition-colors text-sm"
              />
              <Button onClick={() => runMutation.mutate()} disabled={!target.trim() || runMutation.isPending} loading={runMutation.isPending} color="amber">
                Fuzz
              </Button>
            </div>

            <button
              onClick={() => setShowOptions(!showOptions)}
              className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
            >
              {showOptions ? '[-] Hide options' : '[+] Advanced options'}
            </button>

            {showOptions && (
              <div className="space-y-3">
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
                  <Input label="Threads" type="number" min={1} max={50} value={threads} onChange={(e) => setThreads(Number(e.target.value))} />
                  <Input label="Timeout (s)" type="number" min={1} max={60} value={timeout} onChange={(e) => setTimeout(Number(e.target.value))} />
                  <Input label="Max dirs" type="number" min={10} max={2000} value={maxDirs} onChange={(e) => setMaxDirs(Number(e.target.value))} />
                  <Input label="Max crawl pages" type="number" min={1} max={200} value={maxCrawl} onChange={(e) => setMaxCrawl(Number(e.target.value))} />
                  <Input label="Max param tests" type="number" min={1} max={1000} value={maxParamTests} onChange={(e) => setMaxParamTests(Number(e.target.value))} />
                  <Input label="Recursion depth" type="number" min={0} max={5} value={maxDepth} onChange={(e) => setMaxDepth(Number(e.target.value))} />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <Input label="File extensions (comma separated)" value={extensions} onChange={(e) => setExtensions(e.target.value)} placeholder="php, asp, jsp, bak, sql" />
                  <Input label="Extra wordlist (comma separated or file path)" value={wordlist} onChange={(e) => setWordlist(e.target.value)} placeholder="backup.sql, tmp, phpinfo.php" />
                </div>
                <Input label="Extra headers (comma separated: Name: value)" value={extraHeaders} onChange={(e) => setExtraHeaders(e.target.value)} placeholder="X-Forwarded-For: 127.0.0.1, Authorization: Bearer xyz" />
                <div className="text-xs text-gray-500 mt-1">
                  WAF bypass: obfuscated payloads (base64 / hex / octal) and spoofed client headers for WAF/IPS evasion.
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  {Object.entries(toggles).map(([key, val]) => (
                    <button
                      key={key}
                      onClick={() => toggle(key as keyof typeof toggles)}
                      className={clsx(
                        'flex items-center gap-2 px-3 py-2.5 rounded-lg text-xs transition-colors min-h-[44px]',
                        val
                          ? 'bg-webforge-600/20 text-webforge-400 border border-webforge-600/30'
                          : 'bg-gray-800 text-gray-500 border border-gray-700',
                      )}
                    >
                      <div className={`w-3 h-3 rounded-sm ${val ? 'bg-webforge-400' : 'bg-gray-600'}`} />
                      {key.replace(/_/g, ' ')}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Card>
      </PageHeader>

      {runMutation.isPending && <Spinner text="Fuzzing directories and testing parameters..." color="amber" />}

      {runMutation.isError && (
        <Card className="border-red-800/30 bg-red-900/10">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <div className="min-w-0">
              <div className="text-sm text-red-300 font-medium">
                Scan failed{errStatus === 500 ? ' — error on the server' : ''}
              </div>
              <div className="text-xs text-red-200/80 break-words mt-0.5">
                {getErrorMessage(runMutation.error)}
              </div>
              {errStatus === 500 && (
                <div className="text-[11px] text-gray-500 mt-1">
                  The target may be slow, blocking the scanner, or the module hit an unexpected error. Try fewer threads or a lower max param tests and re-run.
                </div>
              )}
            </div>
          </div>
        </Card>
      )}

      {runMutation.data && (
        <div className="space-y-4">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-amber-400 font-medium">{runMutation.data.target}</span>
            {runMutation.data.server && (
              <span className="text-gray-500">· {runMutation.data.server}</span>
            )}
          </div>
          <Stats stats={[
            { label: 'Paths Found', value: runMutation.data.totals?.dirs ?? 0, color: 'amber', icon: <FolderOpen className="w-4 h-4" /> },
            { label: 'Soft-404 Filtered', value: runMutation.data.totals?.soft404 ?? 0, color: 'gray', icon: <AlertTriangle className="w-4 h-4" /> },
            { label: 'Pages Crawled', value: runMutation.data.totals?.pages ?? 0, color: 'cyan', icon: <Globe className="w-4 h-4" /> },
            { label: 'Params Found', value: runMutation.data.totals?.params ?? 0, color: 'blue', icon: <FileSearch className="w-4 h-4" /> },
            { label: 'RCE', value: runMutation.data.totals?.rce ?? 0, color: rce.length > 0 ? 'red' : 'gray', icon: <Bug className="w-4 h-4" /> },
            { label: 'XSS', value: runMutation.data.totals?.xss ?? 0, color: xss.length > 0 ? 'yellow' : 'gray', icon: <Bug className="w-4 h-4" /> },
          ]} />

          <Table
            title="Discovered Directories"
            color="amber"
            columns={['Path', 'Status', 'Size', 'Redirect / Note']}
            rows={runMutation.data.directories.map((d) => [
              <span key="u" className="text-amber-400 truncate max-w-[260px] sm:max-w-md block">{d.url}</span>,
              <span key="s" className={d.status >= 400 ? 'text-orange-400' : 'text-green-400'}>{d.status}</span>,
              d.size,
              <span key="n" className="text-gray-500 truncate max-w-[200px] block">{d.note || d.redirect || ''}</span>,
            ])}
          />

          {runMutation.data.spider.endpoints.length > 0 && (
            <Table
              title="Endpoints & Parameters"
              color="cyan"
              columns={['Method', 'Path', 'Parameters']}
              rows={runMutation.data.spider.endpoints.map((e) => [
                <span key="m" className={e.method === 'POST' ? 'text-green-400' : 'text-cyan-400'}>{e.method}</span>,
                <span key="p" className="text-gray-300 font-mono truncate max-w-[200px] sm:max-w-sm block">{e.path}</span>,
                <span key="params" className="text-xs">
                  {Object.entries(e.params).map(([name, src]) => (
                    <span key={name} className="inline-flex items-center gap-1 mr-2 mb-1">
                      <span className="text-yellow-400 font-mono">{name}</span>
                      <span className="text-gray-600 text-[10px]">{src}</span>
                    </span>
                  ))}
                </span>,
              ])}
            />
          )}

          {runMutation.data.spider.forms.length > 0 && (
            <Table
              title="Forms Discovered"
              color="green"
              columns={['Action', 'Method', 'Fields']}
              rows={runMutation.data.spider.forms.map((f) => [
                <span key="a" className="text-green-400 truncate max-w-[260px] block">{f.action}</span>,
                <span key="m" className="text-yellow-400">{f.method}</span>,
                <span key="f" className="text-gray-300">{f.params.join(', ')}</span>,
              ])}
            />
          )}

          {rce.length === 0 && xss.length === 0 ? (
            <EmptyState
              icon={<CheckCircle className="w-10 h-10" />}
              title="No injection findings"
              description="Parameters tested clean for RCE and XSS"
            />
          ) : (
            <div className="space-y-4">
              {rce.length > 0 && (
                <Card className="border-red-800/30">
                  <div className="mb-3">
                    <SectionHeader
                      icon={<Bug className="w-5 h-5 text-red-400" />}
                      title="Command Injection (RCE)"
                      action={<span className="text-xs text-gray-500">({rce.length})</span>}
                    />
                  </div>
                  <div className="space-y-2">
                    {rce.map((f, i) => (
                      <FindingCard key={i} f={f} color="red" />
                    ))}
                  </div>
                </Card>
              )}
              {xss.length > 0 && (
                <Card className="border-yellow-800/30">
                  <div className="mb-3">
                    <SectionHeader
                      icon={<Globe className="w-5 h-5 text-yellow-400" />}
                      title="Reflected XSS"
                      action={<span className="text-xs text-gray-500">({xss.length})</span>}
                    />
                  </div>
                  <div className="space-y-2">
                    {xss.map((f, i) => (
                      <FindingCard key={i} f={f} color="yellow" />
                    ))}
                  </div>
                </Card>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function FindingCard({ f, color }: { f: FuzzFinding; color: 'red' | 'yellow' }) {
  const isInfo = f.severity === 'INFO' || f.context === 'non_html'
  const accent = isInfo ? 'text-gray-300' : color === 'red' ? 'text-red-400' : 'text-yellow-400'
  const badge = isInfo
    ? 'bg-gray-800/60 text-gray-400'
    : color === 'red'
      ? 'bg-red-900/20 text-red-400'
      : 'bg-yellow-900/20 text-yellow-400'

  const sevColor = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'text-red-300' : f.severity === 'MEDIUM' ? 'text-orange-300' : 'text-gray-400'

  return (
    <div className="bg-gray-900/40 rounded-lg p-3 border border-gray-800/40">
      <div className="flex flex-wrap items-center gap-2">
        <span className={clsx('text-xs font-bold px-1.5 py-0.5 rounded', badge)}>
          {f.severity} · {f.method}
        </span>
        {f.context && f.context !== 'non_html' && (
          <span className={clsx('text-[10px] px-1.5 py-0.5 rounded border', sevColor, 'border-current/30 bg-gray-900/40')}>
            {f.context}
          </span>
        )}
        {f.confidence && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800/80 text-gray-400 border border-gray-700">
            conf: {f.confidence}
          </span>
        )}
        <span className="text-xs font-mono text-gray-300">{f.url}</span>
      </div>
      <div className={clsx('mt-1.5 text-xs font-medium', accent)}>
        Parameter: {f.param}
        {f.context === 'non_html' && <span className="ml-2 text-gray-500 font-normal">reflection into non-HTML body (informational)</span>}
      </div>
      <OutputBlock className="mt-1" maxHeight="max-h-none">{f.payload}</OutputBlock>
      <div className="mt-1.5 text-xs text-gray-400">
        <span className="text-gray-600 mr-1">Technique:</span>{f.technique}
      </div>
      <div className="mt-0.5 text-xs text-gray-400">
        <span className="text-gray-600 mr-1">Evidence:</span>{f.evidence}
      </div>
      {f.param_map && Object.keys(f.param_map).length > 0 && (
        <div className="mt-1.5 text-[10px] text-gray-600">
          Full param map: {Object.entries(f.param_map).map(([k, v]) => `${k}(${v})`).join(', ')}
        </div>
      )}
    </div>
  )
}
