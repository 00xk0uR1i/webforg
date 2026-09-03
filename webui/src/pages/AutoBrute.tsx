import { useState } from 'react'
import { Cpu, CheckCircle, XCircle, AlertTriangle } from 'lucide-react'
import { PageHeader, Card, Input, Button, Stats, Spinner } from '../components/UI'
import { useApiMutation } from '../hooks/useApiMutation'
import api from '../api'
import type { AutoBruteResult } from '../types'

export default function AutoBrute() {
  const [target, setTarget] = useState('')
  const [credsFile, setCredsFile] = useState('')
  const [depth, setDepth] = useState('1')
  const [result, setResult] = useState<AutoBruteResult | null>(null)

  const mutation = useApiMutation<void, AutoBruteResult>(
    async () => {
      const res = await api.post<AutoBruteResult>('/auto-brute', { target, creds_file: credsFile, depth: parseInt(depth) })
      return res.data
    },
    setResult,
  )

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader title="Auto Brute" subtitle="Automatically discover login forms and brute force them with user:pass combos" icon={<Cpu className="w-8 h-8" />} color="red">
        <Card>
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <Input label="Target URL" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://example.com" />
            <Input label="Credentials File" value={credsFile} onChange={(e) => setCredsFile(e.target.value)} placeholder="/path/to/creds.txt" />
            <Input label="Depth" type="number" value={depth} onChange={(e) => setDepth(e.target.value)} min="1" max="3" />
            <div className="flex items-end">
              <Button onClick={() => mutation.mutate()} disabled={!target || !credsFile || mutation.isPending} loading={mutation.isPending} className="w-full">
                Auto Brute
              </Button>
            </div>
          </div>
          <p className="text-xs text-gray-500 mt-2">Credentials file format: user:pass (one per line)</p>
        </Card>
      </PageHeader>

      {mutation.isError && (
        <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 flex items-center gap-2">
          <XCircle className="w-5 h-5 text-red-500" />
          <span className="text-red-300 text-sm">Attack failed. Check target and credentials file.</span>
        </div>
      )}

      {mutation.isPending && <Spinner text="Attacking..." color="red" />}

      {result && (
        <div className="space-y-4">
          <Stats stats={[
            { label: 'Credentials Found', value: result.found.length, color: result.found.length > 0 ? 'green' : undefined },
            { label: 'Forms Tested', value: result.forms_tested },
          ]} />
          {result.found.length > 0 && (
            <Card className="border-green-800/30 bg-green-900/10">
              <div className="space-y-3">
                {result.found.map((cred, i) => (
                  <div key={i} className="flex items-center gap-3">
                    <CheckCircle className="w-5 h-5 text-green-500 shrink-0" />
                    <div>
                      <div className="font-mono text-green-400">{cred.username}:{cred.password}</div>
                      <div className="text-xs text-gray-500">Found at: {cred.form_url}</div>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}
          {result.found.length === 0 && (
            <Card className="border-yellow-800/30 bg-yellow-900/10">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-yellow-500" />
                <span className="text-yellow-400 text-sm">No valid credentials found</span>
              </div>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}
