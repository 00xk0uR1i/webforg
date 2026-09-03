import { useState } from 'react'
import api from '../api'
import { Database } from 'lucide-react'
import { PageHeader, Card, Input, Button, Stats, Table, Spinner } from '../components/UI'
import type { StuffResult } from '../types'

export default function CredStuffing() {
  const [url, setUrl] = useState('')
  const [credsFile, setCredsFile] = useState('')
  const [threads, setThreads] = useState(5)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<StuffResult | null>(null)

  const run = async () => {
    if (!url.trim() || !credsFile.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const { data } = await api.post<StuffResult>('/creds', {
        url: url.trim(),
        creds_file: credsFile.trim(),
        threads,
      })
      setResult(data)
    } catch (e) {
      setResult({ success: false, found: [], total: 0, locked: 0, error: e instanceof Error ? e.message : String(e) })
    }
    setLoading(false)
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader title="Credential Stuffing" subtitle="Test leaked username:password combos against a target login" icon={<Database className="w-8 h-8" />} color="cyan">
        <Card>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Input label="Target Login URL" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://target.com/login" />
            <Input label="Credentials File (user:pass)" value={credsFile} onChange={(e) => setCredsFile(e.target.value)} placeholder="/path/to/creds.txt" />
            <Input label="Threads" type="number" value={threads} onChange={(e) => setThreads(Number(e.target.value))} min={1} max={20} />
          </div>
          <Button onClick={run} disabled={loading || !url.trim() || !credsFile.trim()} loading={loading} color="cyan" className="mt-4">
            Start Credential Stuffing
          </Button>
        </Card>
      </PageHeader>

      {loading && <Spinner text="Testing credentials..." color="cyan" />}

      {result?.success && (
        <div className="space-y-4">
          <Stats stats={[
            { label: 'Tested', value: result.total || 0 },
            { label: 'Valid', value: result.found?.length || 0, color: result.found?.length > 0 ? 'green' : undefined },
            { label: 'Locked', value: result.locked || 0, color: (result.locked || 0) > 0 ? 'yellow' : undefined },
          ]} />
          {result.found?.length > 0 && (
            <Table
              title="Valid Credentials"
              color="green"
              columns={['Username', 'Password', 'Details']}
              rows={result.found.map((c) => [c.username, <span key="p" className="text-yellow-400">{c.password}</span>, c.details || 'OK'])}
            />
          )}
        </div>
      )}
    </div>
  )
}
