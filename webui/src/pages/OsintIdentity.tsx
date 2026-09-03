import { useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Fingerprint, Search, ExternalLink, ChevronDown, User, Mail, Phone, Image, Upload, FolderUp, RefreshCw } from 'lucide-react'
import api from '../api'
import { PageHeader, Card, Button, Spinner, Stats } from '../components/UI'
import { StatusBadge } from '../features/common/badges'
import type {
  OsintIdentityFinding,
  OsintIdentityRunResponse,
  OsintUploadResponse,
  OsintFaceFilesResponse,
  SetOptionResponse,
} from '../types'

const MODULE_PATH = 'auxiliary/gather/osint_identity'

const LOOKUPS = [
  { id: 'all', label: 'All' },
  { id: 'username', label: 'Username' },
  { id: 'email', label: 'Email' },
  { id: 'photo', label: 'Photo' },
  { id: 'phone', label: 'Phone' },
]

const vectorMeta: Record<string, { icon: typeof User; label: string; color: string }> = {
  username: { icon: User, label: 'Username', color: 'text-cyan-400' },
  email: { icon: Mail, label: 'Email', color: 'text-purple-400' },
  phone: { icon: Phone, label: 'Phone', color: 'text-amber-400' },
  photo: { icon: Image, label: 'Photo', color: 'text-green-400' },
}

const MAX_UPLOAD_MB = 25

export default function OsintIdentity() {
  const queryClient = useQueryClient()
  const [input, setInput] = useState('')
  const [lookup, setLookup] = useState('all')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [photoDir, setPhotoDir] = useState('')
  const [photoUrl, setPhotoUrl] = useState('')
  const [threads, setThreads] = useState('8')
  const [timeout, setTimeout_] = useState('10')
  const [country, setCountry] = useState('US')
  const [hibpKey, setHibpKey] = useState('')
  const [showJson, setShowJson] = useState(false)
  const [uploadMsg, setUploadMsg] = useState<string | null>(null)

  const targetFileRef = useRef<HTMLInputElement>(null)
  const refFileRef = useRef<HTMLInputElement>(null)

  const mutation = useMutation({
    mutationFn: async () => {
      const opts: Array<[string, string]> = [
        ['INPUT', input.trim()],
        ['LOOKUP', lookup],
        ['PHOTO_DIR', photoDir],
        ['PHOTO_URL', photoUrl],
        ['THREADS', threads],
        ['TIMEOUT', timeout],
        ['COUNTRY', country],
        ['HIBP_API_KEY', hibpKey],
      ]
      for (const [name, value] of opts) {
        if (value) await api.post<SetOptionResponse>('/modules/set-option', { module_path: MODULE_PATH, name, value })
      }
      const res = await api.post<OsintIdentityRunResponse>('/modules/run', { module_path: MODULE_PATH })
      return res.data
    },
  })

  const targetUpload = useMutation({
    mutationFn: async (file: File) => {
      const fd = new FormData()
      fd.append('file', file)
      const res = await api.post<OsintUploadResponse>('/osint/upload?kind=target', fd)
      return res.data
    },
    onSuccess: (data) => {
      setInput(data.path)
      setPhotoUrl((prev) => prev || '')
      setUploadMsg(`Uploaded ${data.filename} — INPUT set to server path. Optionally set PHOTO_URL for reverse image search.`)
    },
    onError: (e) => setUploadMsg((e as { userMessage?: string } | null)?.userMessage || 'Upload failed'),
  })

  const refUpload = useMutation({
    mutationFn: async (files: File[]) => {
      for (const file of files) {
        const fd = new FormData()
        fd.append('file', file)
        await api.post<OsintUploadResponse>('/osint/upload?kind=reference', fd)
      }
    },
    onSuccess: async (_, files) => {
      setPhotoDir(faceData?.dir || '')
      setUploadMsg(`Uploaded ${files.length} reference photo(s) to the face-match set.`)
      await queryClient.invalidateQueries({ queryKey: ['osint-facefiles'] })
    },
    onError: (e) => setUploadMsg((e as { userMessage?: string } | null)?.userMessage || 'Reference upload failed'),
  })

  const { data: faceData } = useQuery<OsintFaceFilesResponse>({
    queryKey: ['osint-facefiles'],
    queryFn: async () => { const res = await api.get<OsintFaceFilesResponse>('/osint/facefiles'); return res.data },
  })

  const faceFiles = faceData?.files || []

  const run = mutation.data
  const handleRun = () => {
    if (!input.trim()) return
    setShowJson(false)
    mutation.mutate()
  }

  const handleTargetPick = (files: FileList | null) => {
    if (!files || files.length === 0) return
    const f = files[0]
    if (f.size > MAX_UPLOAD_MB * 1024 * 1024) { setUploadMsg(`File too large (max ${MAX_UPLOAD_MB}MB)`); return }
    setUploadMsg(null)
    targetUpload.mutate(f)
  }

  const handleRefPick = (files: FileList | null) => {
    if (!files || files.length === 0) return
    const list = Array.from(files)
    if (list.some((f) => f.size > MAX_UPLOAD_MB * 1024 * 1024)) { setUploadMsg(`One or more files too large (max ${MAX_UPLOAD_MB}MB)`); return }
    setUploadMsg(null)
    refUpload.mutate(list)
  }

  const found = run?.findings.filter((f) => f.status === 'found') || []
  const categories = run ? [...new Set(run.findings.map((f) => f.category))] : []

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader
        title="OSINT Identity"
        subtitle="Correlate a person by username, email, phone, or photo — presence checks, reverse image search, and local face matching."
        icon={<Fingerprint className="w-8 h-8" />}
        color="cyan"
      />

      {/* Controls */}
      <Card>
        <div className="flex flex-wrap gap-2 mb-4">
          {LOOKUPS.map((l) => (
            <button
              key={l.id}
              onClick={() => setLookup(l.id)}
              className={`text-sm px-4 py-2.5 rounded-lg border transition-colors min-h-[44px] ${
                lookup === l.id
                  ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-400'
                  : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'
              }`}
            >
              {l.label}
            </button>
          ))}
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1 min-w-0">
            <Fingerprint className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleRun()}
              placeholder="Username, email, phone number, or path to a photo..."
              className="w-full pl-10 pr-4 py-3 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white placeholder-gray-500 focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors min-h-[44px]"
            />
          </div>
          <Button color="cyan" onClick={handleRun} loading={mutation.isPending} disabled={!input.trim()}>
            <Search className="w-4 h-4 mr-2" /> {mutation.isPending ? 'Investigating...' : 'Investigate'}
          </Button>
        </div>
        <p className="text-[11px] text-gray-600 mt-2">
          Input type is auto-detected: an uploaded/existing file path → photo, an email → email, a long number → phone, otherwise username.
        </p>

        {/* Uploads */}
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <input ref={targetFileRef} type="file" accept="image/*" className="hidden" onChange={(e) => { handleTargetPick(e.target.files); e.target.value = '' }} />
            <button
              onClick={() => targetFileRef.current?.click()}
              disabled={targetUpload.isPending}
              className="w-full flex items-center gap-3 px-4 py-3 rounded-lg border border-dashed border-gray-700 text-left text-gray-300 hover:border-cyan-500/50 hover:text-cyan-300 transition-colors disabled:opacity-50 min-h-[44px]"
            >
              {targetUpload.isPending ? <Spinner text="Uploading..." color="cyan" /> : (<>
                <Upload className="w-4 h-4 shrink-0 text-cyan-400" />
                <span className="text-xs">Upload target photo — sets INPUT to server path</span>
              </>)}
            </button>
          </div>
          <div>
            <input ref={refFileRef} type="file" accept="image/*" multiple className="hidden" onChange={(e) => { handleRefPick(e.target.files); e.target.value = '' }} />
            <button
              onClick={() => refFileRef.current?.click()}
              disabled={refUpload.isPending}
              className="w-full flex items-center gap-3 px-4 py-3 rounded-lg border border-dashed border-gray-700 text-left text-gray-300 hover:border-cyan-500/50 hover:text-cyan-300 transition-colors disabled:opacity-50 min-h-[44px]"
            >
              {refUpload.isPending ? <Spinner text="Uploading..." color="cyan" /> : (<>
                <FolderUp className="w-4 h-4 shrink-0 text-cyan-400" />
                <span className="text-xs">Upload reference photos for face match — sets PHOTO_DIR</span>
              </>)}
            </button>
          </div>
        </div>

        {faceFiles.length > 0 && (
          <div className="mt-3">
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-[11px] font-bold uppercase tracking-widest text-gray-500">Face-match set ({faceFiles.length})</span>
              <button onClick={() => queryClient.invalidateQueries({ queryKey: ['osint-facefiles'] })} className="p-1 text-gray-500 hover:text-gray-300 min-w-[28px] min-h-[28px] flex items-center justify-center" title="Refresh">
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {faceFiles.map((f) => (
                <span key={f.filename} className="flex items-center gap-1.5 text-[11px] px-2 py-1 rounded bg-gray-800 text-gray-400">
                  {f.filename}
                  <span className="text-gray-600">{(f.size / 1024).toFixed(0)}KB</span>
                </span>
              ))}
            </div>
            <p className="text-[11px] text-gray-600 mt-1.5">PHOTO_DIR: {faceData?.dir || 'not set'}</p>
          </div>
        )}

        {uploadMsg && (
          <div className="mt-3 text-[11px] text-cyan-300/80 bg-cyan-500/5 border border-cyan-500/20 rounded-lg px-3 py-2">{uploadMsg}</div>
        )}

        <button
          onClick={() => setShowAdvanced((p) => !p)}
          className="mt-4 flex items-center gap-2 text-xs text-gray-500 hover:text-gray-300 transition-colors min-h-[32px]"
        >
          <ChevronDown className={`w-4 h-4 transition-transform ${showAdvanced ? 'rotate-180' : ''}`} />
          Advanced options
        </button>

        {showAdvanced && (
          <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
            <div>
              <label className="text-xs text-gray-400 mb-1 block">PHOTO_DIR (face match folder)</label>
              <input value={photoDir} onChange={(e) => setPhotoDir(e.target.value)} placeholder="/opt/photos" className="w-full px-3 py-2 bg-gray-800/80 border border-gray-700/60 rounded-lg text-xs font-mono text-white placeholder-gray-600 focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors" />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">PHOTO_URL (for reverse image search)</label>
              <input value={photoUrl} onChange={(e) => setPhotoUrl(e.target.value)} placeholder="https://host/photo.jpg" className="w-full px-3 py-2 bg-gray-800/80 border border-gray-700/60 rounded-lg text-xs font-mono text-white placeholder-gray-600 focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors" />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">THREADS</label>
              <input type="number" value={threads} onChange={(e) => setThreads(e.target.value)} className="w-full px-3 py-2 bg-gray-800/80 border border-gray-700/60 rounded-lg text-xs font-mono text-white focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors" />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">TIMEOUT (s)</label>
              <input type="number" value={timeout} onChange={(e) => setTimeout_(e.target.value)} className="w-full px-3 py-2 bg-gray-800/80 border border-gray-700/60 rounded-lg text-xs font-mono text-white focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors" />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">COUNTRY (phone region)</label>
              <input value={country} onChange={(e) => setCountry(e.target.value)} className="w-full px-3 py-2 bg-gray-800/80 border border-gray-700/60 rounded-lg text-xs font-mono text-white focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors" />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">HIBP_API_KEY (optional)</label>
              <input value={hibpKey} onChange={(e) => setHibpKey(e.target.value)} placeholder="haveibeenpwned v3 key" className="w-full px-3 py-2 bg-gray-800/80 border border-gray-700/60 rounded-lg text-xs font-mono text-white placeholder-gray-600 focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors" />
            </div>
          </div>
        )}
      </Card>

      {/* Loading */}
      {mutation.isPending && (
        <Card>
          <Spinner text="Running lookups (username checks, Gravatar, face matching)..." color="cyan" />
        </Card>
      )}

      {mutation.isError && (
        <Card>
          <div className="text-sm text-red-400">{((mutation.error as { userMessage?: string } | null)?.userMessage) || 'Run failed'}</div>
        </Card>
      )}

      {/* Results */}
      {run && !mutation.isPending && (
        <div className="space-y-4">
          <Stats stats={[
            { label: 'Vector', value: run.vector, color: 'cyan' },
            { label: 'Found', value: found.length, color: 'green' },
            { label: 'Total Checks', value: run.findings.length },
          ]} />

          <Card>
            <div className="flex items-center gap-2 flex-wrap">
              {(() => {
                const v = vectorMeta[run.vector]
                const Icon = v?.icon || User
                return (
                  <>
                    <Icon className={`w-4 h-4 ${v?.color || 'text-gray-400'}`} />
                    <span className="text-sm font-medium text-gray-100 break-all">{run.input}</span>
                  </>
                )
              })()}
              <button
                onClick={() => setShowJson((p) => !p)}
                className="ml-auto text-[11px] px-2 py-1 rounded text-gray-500 hover:text-gray-300 min-h-[28px]"
              >
                {showJson ? 'Hide JSON' : 'Raw JSON'}
              </button>
            </div>
          </Card>

          {showJson ? (
            <Card>
              <pre className="text-[11px] whitespace-pre-wrap font-mono text-gray-400 break-all max-h-96 overflow-y-auto">
                {JSON.stringify(run, null, 2)}
              </pre>
            </Card>
          ) : (
            categories.map((cat) => (
              <Card key={cat} className="!p-0 overflow-hidden">
                <div className="px-4 py-2.5 border-b border-gray-800/60 bg-gray-800/20 flex items-center gap-2">
                  <span className="text-[11px] font-bold uppercase tracking-widest text-gray-500">{cat}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-500">
                    {run.findings.filter((f) => f.category === cat).length}
                  </span>
                </div>
                <div className="divide-y divide-gray-800/50">
                  {run.findings.filter((f) => f.category === cat).map((f, i) => {
                    return (
                      <div key={i} className="flex items-start gap-3 px-4 py-3">
                        <StatusBadge status={f.status} className="shrink-0 mt-0.5" />
                        <div className="min-w-0 flex-1">
                          <div className="text-sm text-gray-100">{f.item}</div>
                          {f.url && (
                            <a href={f.url} target="_blank" rel="noopener noreferrer" className="text-[11px] text-cyan-400 font-mono break-all hover:underline inline-flex items-center gap-1 mt-0.5">
                              <ExternalLink className="w-3 h-3" /> {f.url}
                            </a>
                          )}
                          {f.detail && <div className="text-[11px] text-gray-500 break-all mt-0.5">{f.detail}</div>}
                        </div>
                      </div>
                    )
                  })}
                </div>
              </Card>
            ))
          )}
        </div>
      )}

      {/* Initial state */}
      {!run && !mutation.isPending && !mutation.isError && (
        <Card className="text-center py-12">
          <Fingerprint className="w-12 h-12 mx-auto mb-3 text-gray-700" />
          <div className="text-sm text-gray-400 font-medium">OSINT Identity Gatherer</div>
          <div className="text-xs text-gray-600 mt-2 max-w-lg mx-auto">
            Enter a username, email, phone number, or photo path. The module checks account presence across 25 sites,
            Gravatar profiles, phone validity, EXIF metadata, and local face matching.
          </div>
          <div className="flex flex-wrap justify-center gap-2 mt-4">
            {['torvalds', '+14155552671'].map((t) => (
              <button
                key={t}
                onClick={() => { setInput(t) }}
                className="text-xs px-3 py-1.5 rounded-lg bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700 transition-colors border border-gray-700 min-h-[36px]"
              >
                {t}
              </button>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
