import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Search, Shield, AlertTriangle, CheckCircle, Key, Lock, Globe, Code, Database, Terminal, Wifi, Eye, FileSearch } from 'lucide-react'
import clsx from 'clsx'
import api from '../api'
import { PageHeader, Card, Input, Button, Stats, Spinner, EmptyState } from '../components/UI'
import type { SecretFinding, SecretScanResult } from '../types'

const severityConfig: Record<string, { color: string; bg: string; icon: typeof Shield }> = {
  CRITICAL: { color: 'text-red-400', bg: 'bg-red-900/20 border-red-800/30', icon: AlertTriangle },
  HIGH: { color: 'text-orange-400', bg: 'bg-orange-900/20 border-orange-800/30', icon: AlertTriangle },
  MEDIUM: { color: 'text-yellow-400', bg: 'bg-yellow-900/20 border-yellow-800/30', icon: Shield },
  LOW: { color: 'text-blue-400', bg: 'bg-blue-900/20 border-blue-800/30', icon: Shield },
  INFO: { color: 'text-gray-400', bg: 'bg-gray-900/20 border-gray-800/30', icon: Eye },
}

const typeIcons: Record<string, typeof Shield> = {
  private_key: Lock, rsa_key: Lock, password: Key, hardcoded_password: Key,
  aws_access_key: Globe, github_token: Code, slack_token: Globe,
  jwt_token: Key, jwt_CRACKED: Lock, credit_card: Database,
  vcs_exposed: FileSearch, debug_endpoint: Terminal, websocket: Wifi,
  graphql_introspection: Code, path_traversal: AlertTriangle,
}

const typeSeverity: Record<string, string> = {
  private_key: 'CRITICAL', rsa_key: 'CRITICAL', dsa_key: 'CRITICAL', ec_key: 'CRITICAL',
  pgp_key: 'CRITICAL', ed25519_key: 'CRITICAL', age_key: 'CRITICAL',
  password: 'HIGH', hardcoded_password: 'HIGH', env_password: 'HIGH',
  aws_access_key: 'CRITICAL', aws_secret_key: 'CRITICAL', aws_session_token: 'CRITICAL',
  azure_storage_key: 'CRITICAL', azure_sas: 'CRITICAL', gcp_key: 'CRITICAL',
  jwt_token: 'MEDIUM', jwt_CRACKED: 'CRITICAL', jwt_ALG_NONE: 'CRITICAL',
  slack_token: 'HIGH', github_token: 'HIGH', github_fine_grained: 'CRITICAL',
  github_oauth: 'HIGH', gitlab_token: 'HIGH', gitlab_pipeline: 'HIGH',
  bitbucket_token: 'HIGH', npm_token: 'HIGH', pypi_token: 'HIGH',
  digitalocean_token: 'HIGH', vault_token: 'HIGH', sendgrid_key: 'HIGH',
  stripe_key: 'CRITICAL', twilio_key: 'HIGH', square_token: 'HIGH',
  shopify_token: 'HIGH', heroku_api_key: 'HIGH', paypal_token: 'MEDIUM',
  google_api_key: 'MEDIUM', google_oauth: 'MEDIUM', firebase_key: 'HIGH',
  telegram_token: 'HIGH', discord_token: 'HIGH', discord_webhook: 'HIGH',
  credit_card: 'CRITICAL', ssn: 'CRITICAL', iban: 'HIGH',
  vcs_exposed: 'CRITICAL', cloud_metadata: 'CRITICAL',
  cors_misconfig: 'HIGH', webdav_enabled: 'HIGH', backup_file: 'HIGH',
  debug_endpoint: 'HIGH', error_info_leak: 'MEDIUM', path_traversal: 'CRITICAL',
  graphql_introspection: 'MEDIUM', graphql_sensitive_types: 'HIGH',
  auth_header_leak: 'HIGH', connection_string: 'HIGH', database_url: 'HIGH',
  dsn_string: 'MEDIUM', header_leak: 'MEDIUM', cookie_session: 'MEDIUM',
  missing_security_headers: 'LOW', jwks_endpoint: 'INFO', source_map: 'MEDIUM',
  websocket: 'MEDIUM', hidden_input: 'MEDIUM', meta_secret: 'MEDIUM',
  html_comment_secret: 'LOW', eval_usage: 'HIGH', dangerous_function: 'HIGH',
  sql_query: 'MEDIUM', file_read: 'MEDIUM',
  md5_CRACKED: 'HIGH', sha1_CRACKED: 'HIGH', sha256_CRACKED: 'HIGH', sha512_CRACKED: 'HIGH',
  ntlm_hash: 'CRITICAL', mysql_hash: 'HIGH', base64_decoded: 'MEDIUM',
  internal_url: 'MEDIUM', metadata_url: 'CRITICAL',
}

function getSeverity(f: SecretFinding): string {
  return f.severity || typeSeverity[f.type] || 'INFO'
}

function GettingIcon({ type }: { type: string }) {
  const Icon = typeIcons[type] || Shield
  const sev = getSeverity({ type } as SecretFinding)
  const color = sev === 'CRITICAL' ? 'text-red-400' : sev === 'HIGH' ? 'text-orange-400' : sev === 'MEDIUM' ? 'text-yellow-400' : 'text-gray-400'
  return <Icon className={`w-4 h-4 shrink-0 ${color}`} />
}

export default function SecretScan() {
  const [target, setTarget] = useState('')
  const [depth, setDepth] = useState(3)
  const [result, setResult] = useState<SecretScanResult | null>(null)
  const [showOptions, setShowOptions] = useState(false)
  const [options, setOptions] = useState({
    check_git: true, check_cloud: true, check_cors: true,
    check_graphql: true, check_js: true, check_websockets: true,
    crack_hashes: true, crack_jwt: true,
  })

  const scanMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post<SecretScanResult>('/secret-scan', {
        target: target.trim(),
        depth,
        threads: 10,
        timeout: 10,
        ...options,
      })
      return res.data
    },
    onSuccess: (data) => setResult(data),
  })

  const findings = result?.findings || []
  const grouped: Record<string, SecretFinding[]> = {}
  for (const f of findings) {
    const sev = getSeverity(f)
    if (!grouped[sev]) grouped[sev] = []
    grouped[sev].push(f)
  }

  const toggleOption = (key: string) => {
    setOptions((p) => ({ ...p, [key]: !p[key as keyof typeof p] }))
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader
        title="Secret Scanner ELITE"
        subtitle="12-phase sensitive data discovery with 84+ detection patterns, JWT analysis, hash cracking, and cloud metadata extraction"
        icon={<Search className="w-8 h-8" />}
        color="red"
      >
        <Card>
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row gap-2">
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && target.trim() && scanMutation.mutate()}
                placeholder="https://target.com"
                className="flex-1 min-w-0 bg-gray-800/80 border border-gray-700/60 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:border-red-500/60 focus:ring-1 focus:ring-red-500/20 outline-none transition-colors text-sm"
              />
              <input
                type="number"
                value={depth}
                onChange={(e) => setDepth(Number(e.target.value))}
                min={1}
                max={5}
                className="w-full sm:w-20 bg-gray-800/80 border border-gray-700/60 rounded-lg px-3 py-3 text-white focus:border-red-500/60 focus:ring-1 focus:ring-red-500/20 outline-none transition-colors text-sm text-center"
                title="Crawl depth"
              />
              <button
                onClick={() => scanMutation.mutate()}
                disabled={!target.trim() || scanMutation.isPending}
                className="bg-red-600 hover:bg-red-500 disabled:bg-gray-700 text-white font-bold px-6 py-3 rounded-lg transition-colors text-sm min-h-[44px] flex items-center justify-center gap-2"
              >
                {scanMutation.isPending ? (
                  <><div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" /> Scanning...</>
                ) : (
                  <><Search className="w-4 h-4" /> Scan</>
                )}
              </button>
            </div>

            <button
              onClick={() => setShowOptions(!showOptions)}
              className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
            >
              {showOptions ? '[-] Hide options' : '[+] Advanced options'}
            </button>

            {showOptions && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {Object.entries(options).map(([key, val]) => (
                  <button
                    key={key}
                    onClick={() => toggleOption(key)}
                    className={clsx(
                      'flex items-center gap-2 px-3 py-2.5 rounded-lg text-xs transition-colors min-h-[44px]',
                      val
                        ? 'bg-webforge-600/20 text-webforge-400 border border-webforge-600/30'
                        : 'bg-gray-800 text-gray-500 border border-gray-700',
                    )}
                  >
                    <div className={`w-3 h-3 rounded-sm ${val ? 'bg-webforge-400' : 'bg-gray-600'}`} />
                    {key.replace(/_/g, ' ').replace('check ', '').replace('crack ', '')}
                  </button>
                ))}
              </div>
            )}
          </div>
        </Card>
      </PageHeader>

      {scanMutation.isPending && (
        <Card>
          <div className="flex flex-col items-center gap-3 py-6">
            <div className="w-10 h-10 border-3 border-red-400 border-t-transparent rounded-full animate-spin" />
            <div className="text-center">
              <div className="text-sm text-gray-300 font-medium">Running 12-phase elite scan...</div>
              <div className="text-xs text-gray-500 mt-1">This may take a while depending on target size</div>
            </div>
          </div>
        </Card>
      )}

      {scanMutation.isError && (
        <Card className="border-red-800/30 bg-red-900/10">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
            <div>
              <div className="text-sm text-red-300 font-medium">Scan failed</div>
              <div className="text-xs text-gray-500">{scanMutation.error?.message || 'Unknown error'}</div>
            </div>
          </div>
        </Card>
      )}

      {result && (
        <div className="space-y-4">
          <Stats stats={[
            { label: 'Total Findings', value: result.total, color: 'red' },
            { label: 'Critical', value: result.critical, color: result.critical > 0 ? 'red' : undefined },
            { label: 'High', value: result.high, color: result.high > 0 ? 'yellow' : undefined },
            { label: 'Cracked', value: result.cracked, color: result.cracked > 0 ? 'green' : undefined },
          ]} />

          {findings.length === 0 ? (
            <EmptyState
              icon={<CheckCircle className="w-10 h-10" />}
              title="No secrets found"
              description="Target appears clean"
            />
          ) : (
            <div className="space-y-3">
              {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map((sev) => {
                const items = grouped[sev]
                if (!items || items.length === 0) return null
                const cfg = severityConfig[sev]
                const Icon = cfg.icon
                return (
                  <Card key={sev} className={cfg.bg}>
                    <div className="flex items-center gap-2 mb-3">
                      <Icon className={`w-5 h-5 ${cfg.color}`} />
                      <h3 className={`font-bold text-sm ${cfg.color}`}>{sev}</h3>
                      <span className="text-xs text-gray-500">({items.length})</span>
                    </div>
                    <div className="space-y-2">
                      {items.map((f, i) => (
                        <div key={i} className="bg-gray-900/40 rounded-lg p-3 border border-gray-800/40">
                          <div className="flex items-start gap-2">
                            <GettingIcon type={f.type} />
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-gray-800 text-gray-300">{f.type.replace(/_/g, ' ')}</span>
                                {f.cracked && (
                                  <span className="text-xs px-1.5 py-0.5 rounded bg-green-400/10 text-green-400 font-medium">
                                    CRACKED: {f.cracked}
                                  </span>
                                )}
                                {f.jwt_secret_cracked && (
                                  <span className="text-xs px-1.5 py-0.5 rounded bg-green-400/10 text-green-400 font-medium">
                                    JWT SECRET: {f.jwt_secret_cracked}
                                  </span>
                                )}
                                {f.hash_type && (
                                  <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-400/10 text-yellow-400">
                                    {f.hash_type}
                                  </span>
                                )}
                                {f.jwt_algorithm && (
                                  <span className="text-xs px-1.5 py-0.5 rounded bg-purple-400/10 text-purple-400">
                                    {f.jwt_algorithm}
                                  </span>
                                )}
                              </div>
                              <div className="mt-1.5 font-mono text-xs text-gray-300 break-all bg-gray-950/50 rounded p-2">
                                {f.value.length > 200 ? f.value.substring(0, 200) + '...' : f.value}
                              </div>
                              <div className="mt-1.5 flex items-center gap-3 text-[10px] text-gray-600">
                                <span className="truncate max-w-[300px]">{f.url}</span>
                                {f.branch && <span>Branch: {f.branch}</span>}
                              </div>
                              {f.jwt_vulnerabilities && f.jwt_vulnerabilities.length > 0 && (
                                <div className="mt-2 space-y-1">
                                  {f.jwt_vulnerabilities.map((v, j) => (
                                    <div key={j} className="flex items-center gap-1.5 text-xs">
                                      <AlertTriangle className="w-3 h-3 text-red-400 shrink-0" />
                                      <span className="text-red-400">{v}</span>
                                    </div>
                                  ))}
                                </div>
                              )}
                              {f.jwt_secrets && f.jwt_secrets.length > 0 && (
                                <div className="mt-2 space-y-1">
                                  {f.jwt_secrets.map((s, j) => (
                                    <div key={j} className="flex items-center gap-1.5 text-xs">
                                      <Key className="w-3 h-3 text-yellow-400 shrink-0" />
                                      <span className="text-yellow-400">{s}</span>
                                    </div>
                                  ))}
                                </div>
                              )}
                              {f.decoded && (
                                <div className="mt-2 text-xs text-gray-500 bg-gray-950/50 rounded p-2 font-mono break-all">
                                  Decoded: {f.decoded.length > 150 ? f.decoded.substring(0, 150) + '...' : f.decoded}
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </Card>
                )
              })}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
