import { useState } from 'react'
import api from '../api'
import { Key } from 'lucide-react'
import { PageHeader, Card, Input, Button, Stats, Table, Spinner } from '../components/UI'
import type { SprayResult } from '../types'

export default function PasswordSpray() {
  const [url, setUrl] = useState('')
  const [usernames, setUsernames] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<SprayResult | null>(null)

  const run = async () => {
    if (!url.trim() || !usernames.trim() || !password.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const { data } = await api.post<SprayResult>('/spray', {
        url: url.trim(),
        usernames: usernames.trim(),
        passwords: password.trim(),
      })
      setResult(data)
    } catch (e) {
      setResult({ success: false, found: [], total: 0, error: e instanceof Error ? e.message : String(e) })
    }
    setLoading(false)
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader title="Password Spray" subtitle="Test one password against multiple usernames to avoid lockout" icon={<Key className="w-8 h-8" />} color="blue">
        <Card>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Input label="Target Login URL" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://target.com/login" />
            <Input label="Password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Company2024!" />
            <div className="sm:col-span-2">
              <Input label="Usernames (comma-separated)" value={usernames} onChange={(e) => setUsernames(e.target.value)} placeholder="admin,john,alice,bob" />
            </div>
          </div>
          <Button onClick={run} disabled={loading || !url.trim() || !usernames.trim() || !password.trim()} loading={loading} color="blue" className="mt-4">
            Start Password Spray
          </Button>
        </Card>
      </PageHeader>

      {loading && <Spinner text="Spraying password across accounts..." color="blue" />}

      {result?.success && (
        <div className="space-y-4">
          <Stats stats={[
            { label: 'Accounts Tested', value: result.total || 0 },
            { label: 'Valid Found', value: result.found?.length || 0, color: result.found?.length > 0 ? 'green' : undefined },
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
