import { useState } from 'react'
import api from '../api'
import { Zap } from 'lucide-react'
import { PageHeader, Card, Input, Button, Stats, Table, Spinner } from '../components/UI'
import { scanStatusClass } from '../utils/colors'
import type { AutoScanResponse } from '../types'

const CHECKS = [
  { id: 'all', label: 'All Checks' },
  { id: 'sqli', label: 'SQL Injection' },
  { id: 'xss', label: 'XSS' },
  { id: 'lfi', label: 'LFI/RFI' },
  { id: 'ssti', label: 'SSTI' },
  { id: 'ssrf', label: 'SSRF' },
  { id: 'headers', label: 'Security Headers' },
  { id: 'ssl', label: 'SSL/TLS' },
  { id: 'tech', label: 'Fingerprint' },
]

export default function AutoScan() {
  const [url, setUrl] = useState('')
  const [checks, setChecks] = useState('all')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AutoScanResponse | null>(null)

  const run = async () => {
    if (!url.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const { data } = await api.post<AutoScanResponse>('/scan', { url: url.trim(), checks })
      setResult(data)
    } catch {
      setResult({ success: false, url, results: [], vuln_count: 0, elapsed: 0 })
    }
    setLoading(false)
  }

  return (
    <div className="space-y-4 sm:space-y-5">
      <PageHeader title="Auto Scan" subtitle="Run all vulnerability checks against a target in one shot" icon={<Zap className="w-8 h-8" />} color="red">
        <Card>
          <div className="flex flex-col sm:flex-row gap-3">
            <Input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://target.com"
              className="flex-1 min-w-0"
            />
            <select
              value={checks}
              onChange={(e) => setChecks(e.target.value)}
              className="bg-gray-800/80 border border-gray-700/60 rounded-lg px-4 py-2.5 text-white focus:border-red-500/60 focus:ring-1 focus:ring-red-500/20 outline-none text-sm transition-colors"
            >
              {CHECKS.map((c) => (
                <option key={c.id} value={c.id}>{c.label}</option>
              ))}
            </select>
            <Button onClick={run} disabled={loading || !url.trim()} loading={loading}>Scan</Button>
          </div>
          <p className="text-xs text-gray-500 mt-2">SQLi, XSS, LFI, SSTI, SSRF, security headers, SSL/TLS, fingerprint</p>
        </Card>
      </PageHeader>

      {loading && <Spinner text="Running vulnerability scan..." color="red" />}

      {result && (
        <div className="space-y-4">
          <Stats stats={[
            { label: 'Vulnerabilities', value: result.vuln_count, color: 'red' },
            { label: 'Total Checks', value: result.results.length },
            { label: 'Elapsed', value: `${result.elapsed?.toFixed(1)}s`, color: 'green' },
          ]} />
          <Table
            title={`Results — ${result.url}`}
            color="red"
            columns={['Category', 'Check', 'Status', 'Details']}
            rows={result.results.map((r) => [
              <span key="cat" className="text-cyan-400">{r.category}</span>,
              r.check,
              <span key="stat" className={scanStatusClass(r.status)}>{r.status}</span>,
              <span key="det" className="text-gray-300 max-w-[200px] sm:max-w-md truncate">{r.details}</span>,
            ])}
          />
        </div>
      )}
    </div>
  )
}
