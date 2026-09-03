import { useState } from 'react'
import api from '../api'
import { Lock } from 'lucide-react'
import { PageHeader, Card, Input, Button, Stats, Spinner } from '../components/UI'
import type { BruteForceResult } from '../types'

export default function BruteForce() {
  const [url, setUrl] = useState('')
  const [usernames, setUsernames] = useState('')
  const [passwords, setPasswords] = useState('')
  const [threads, setThreads] = useState(1)
  const [delay, setDelay] = useState(0.5)
  const [failString, setFailString] = useState('')
  const [successString, setSuccessString] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<BruteForceResult | null>(null)

  const run = async () => {
    if (!url.trim() || !usernames.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const { data } = await api.post<BruteForceResult>('/bruteforce', {
        url: url.trim(),
        usernames: usernames.trim(),
        passwords: passwords.trim() || undefined,
        threads,
        delay,
        fail_string: failString.trim() || undefined,
        success_string: successString.trim() || undefined,
      })
      setResult(data)
    } catch (e) {
      setResult({ success: false, found: [], attempts: 0, lockout_detected: false, error: e instanceof Error ? e.message : String(e) })
    }
    setLoading(false)
  }

  return (
    <div className="space-y-4 sm:space-y-5">
      <PageHeader title="Brute Force" subtitle="Login form brute force with username/password lists and lockout detection" icon={<Lock className="w-8 h-8" />} color="amber">
        <Card>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Input label="Target Login URL" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://target.com/login" />
            <Input label="Usernames (comma-sep or file path)" value={usernames} onChange={(e) => setUsernames(e.target.value)} placeholder="admin,user1,test" />
            <Input label="Passwords (comma-sep, file, or empty)" value={passwords} onChange={(e) => setPasswords(e.target.value)} placeholder="password123,admin" />
            <div className="grid grid-cols-2 gap-4">
              <Input label="Threads" type="number" value={threads} onChange={(e) => setThreads(Number(e.target.value))} min={1} max={10} />
              <Input label="Delay (s)" type="number" value={delay} onChange={(e) => setDelay(Number(e.target.value))} min={0} step={0.1} />
            </div>
            <Input label="Fail String" value={failString} onChange={(e) => setFailString(e.target.value)} placeholder="Invalid credentials" />
            <Input label="Success String" value={successString} onChange={(e) => setSuccessString(e.target.value)} placeholder="Welcome, dashboard" />
          </div>
          <Button onClick={run} disabled={loading || !url.trim() || !usernames.trim()} loading={loading} color="amber" className="mt-4">
            Start Brute Force
          </Button>
        </Card>
      </PageHeader>

      {loading && <Spinner text="Brute forcing login form..." color="amber" />}

      {result?.success && (
        <div className="space-y-4">
          <Stats stats={[
            { label: 'Valid Found', value: result.found?.length || 0, color: 'green' },
            { label: 'Attempts', value: result.attempts || 0 },
            { label: 'Lockout', value: result.lockout_detected ? 'Yes' : 'No', color: result.lockout_detected ? 'amber' : undefined },
          ]} />
          {result.found?.length > 0 && (
            <Card className="border-green-500/20 bg-green-500/5">
              <h3 className="font-bold text-green-400 mb-2 text-sm">Valid Credentials Found:</h3>
              {result.found.map((c, i) => (
                <div key={i} className="font-mono text-sm">
                  <span className="text-white">{c.username}</span>
                  <span className="text-gray-500">:</span>
                  <span className="text-yellow-400">{c.password}</span>
                  <span className="text-gray-600 ml-2">({c.details})</span>
                </div>
              ))}
            </Card>
          )}
        </div>
      )}
    </div>
  )
}
