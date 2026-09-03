import { useState } from 'react'
import api from '../api'
import { Search } from 'lucide-react'
import { PageHeader, Card, Input, Button, Stats, Table, Spinner } from '../components/UI'
import type { CrawlerResult } from '../types'

export default function FormCrawler() {
  const [url, setUrl] = useState('')
  const [depth, setDepth] = useState(2)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<CrawlerResult | null>(null)

  const run = async () => {
    if (!url.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const { data } = await api.post<CrawlerResult>('/form-crawler', { target: url.trim(), depth })
      setResult(data)
    } catch (e) {
      setResult({ success: false, forms: [], pages_crawled: 0, error: e instanceof Error ? e.message : String(e) })
    }
    setLoading(false)
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader title="Form Crawler" subtitle="Discover and analyze login forms, input fields, and hidden parameters" icon={<Search className="w-8 h-8" />} color="blue">
        <Card>
          <div className="flex flex-col sm:flex-row gap-3">
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://target.com"
              className="flex-1 min-w-0 bg-gray-800/80 border border-gray-700/60 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/20 outline-none transition-colors text-sm"
            />
            <Input label="" type="number" value={depth} onChange={(e) => setDepth(Number(e.target.value))} min={1} max={5} placeholder="Depth" className="w-24" />
            <Button onClick={run} disabled={loading || !url.trim()} loading={loading} color="blue">Crawl</Button>
          </div>
        </Card>
      </PageHeader>

      {loading && <Spinner text="Crawling target for forms..." color="blue" />}

      {result?.success && (
        <div className="space-y-4">
          <Stats stats={[
            { label: 'Forms Found', value: result.forms?.length || 0, color: 'blue' },
            { label: 'Pages Crawled', value: result.pages_crawled || 0 },
          ]} />
          {result.forms?.length > 0 && (
            <Table
              title="Discovered Forms"
              color="blue"
              columns={['Action URL', 'Method', 'User Field', 'Pass Field', 'Hidden Fields', 'CSRF Field']}
              rows={result.forms.map((f) => [
                <span key="u" className="text-cyan-400 truncate max-w-[200px] sm:max-w-md block">{f.action_url}</span>,
                <span key="m" className="text-yellow-400">{f.method || 'POST'}</span>,
                <span key="uf" className="font-mono">{f.user_field || '—'}</span>,
                <span key="pf" className="font-mono">{f.pass_field || '—'}</span>,
                Object.keys(f.hidden_fields || {}).length,
                <span key="c" className="font-mono">{f.csrf_field || 'none'}</span>,
              ])}
            />
          )}
        </div>
      )}
    </div>
  )
}
