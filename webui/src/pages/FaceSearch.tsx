import { useState, useCallback } from 'react'
import { ScanFace, Download, History, Trash2, ShieldAlert } from 'lucide-react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import api from '../api'
import {
  PageHeader,
  Card,
  Button,
  Select,
  EmptyState,
  SectionHeader,
  InlineStatus,
} from '../components/UI'
import { FaceUpload } from '../components/FaceSearch/FaceUpload'
import { FaceStatus } from '../components/FaceSearch/FaceStatus'
import { FaceResultCard, FaceResultDetail } from '../components/FaceSearch/FaceResults'
import { FaceScore } from '../components/FaceSearch/FaceScore'
import {
  DetectedFace,
  FaceSearchHistoryEntry,
  FaceSearchPhase,
  FaceSearchResult,
  FACE_SOURCE_TYPES,
} from '../types/faceSearch'

export default function FaceSearch() {
  const queryClient = useQueryClient()
  const [file, setFile] = useState<File | null>(null)
  const [previewUrl, setPreviewUrl] = useState<string | null>(null)
  const [faces, setFaces] = useState<DetectedFace[]>([])
  const [selectedFace, setSelectedFace] = useState(0)
  const [phase, setPhase] = useState<FaceSearchPhase>('idle')
  const [error, setError] = useState<string | null>(null)
  const [results, setResults] = useState<FaceSearchResult[]>([])
  const [detail, setDetail] = useState<FaceSearchResult | null>(null)
  const [minSim, setMinSim] = useState<number>(0.7)
  const [sourceFilter, setSourceFilter] = useState<string>('')
  const [showIndex, setShowIndex] = useState(false)
  const [exportMsg, setExportMsg] = useState<string | null>(null)

  const { data: providers } = useQuery({
    queryKey: ['face-providers'],
    queryFn: async () => (await api.get('/osint/face/providers')).data,
  })

  const { data: indexData } = useQuery({
    queryKey: ['face-index'],
    queryFn: async () => (await api.get('/osint/face/index')).data,
    enabled: showIndex,
  })

  const handleFile = useCallback((f: File) => {
    setFile(f)
    setError(null)
    setFaces([])
    setSelectedFace(0)
    setResults([])
    setPhase('uploading')
    const url = URL.createObjectURL(f)
    setPreviewUrl(url)
  }, [])

  const handleClear = useCallback(() => {
    setFile(null)
    setPreviewUrl(null)
    setFaces([])
    setSelectedFace(0)
    setResults([])
    setError(null)
    setPhase('idle')
  }, [])

  const detectMutation = useMutation({
    mutationFn: async (f: File) => {
      const fd = new FormData()
      fd.append('file', f)
      return (await api.post('/osint/face/detect', fd)).data
    },
    onSuccess: (data) => {
      const det = data.faces || []
      setFaces(det)
      setSelectedFace(0)
      setPhase(det.length > 1 ? 'face-selection' : 'embedding')
      setError(data.error || (data.message && !det.length ? data.message : null))
    },
    onError: (e) => {
      setPhase('error')
      setError((e as { userMessage?: string } | null)?.userMessage || 'Face detection failed')
    },
  })

  const searchMutation = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error('No image selected')
      return await searchFile(file)
    },
    onSuccess: (data) => {
      const res = data.results || []
      setResults(res)
      setPhase(res.length ? 'results' : 'empty')
      setError(null)
    },
    onError: (e) => {
      setPhase('error')
      setError((e as { userMessage?: string } | null)?.userMessage || 'Face search failed')
    },
  })

  async function searchFile(f: File) {
    if (!faces.length) {
      setPhase('detecting')
      const detect = await api.post('/osint/face/detect', toFormData(f))
      const d = detect.data
      const det = d.faces || []
      if (!det.length) {
        setFaces([])
        setPhase('empty')
        setError(d.message || 'No face detected')
        return { results: [], total: 0 }
      }
      setFaces(det)
      setSelectedFace(0)
    }

    setPhase('embedding')
    const searchFd = new FormData()
    searchFd.append('file', f)
    searchFd.append('face_id', String(selectedFace))
    searchFd.append('min_similarity', String(minSim))
    if (sourceFilter) searchFd.append('source_type', sourceFilter)
    setPhase('searching')
    const searchResp = await api.post('/osint/face/search', searchFd)
    return searchResp.data
  }

  function toFormData(f: File) {
    const fd = new FormData()
    fd.append('file', f)
    return fd
  }

  const handleSearch = () => {
    if (!file || phase === 'searching' || phase === 'embedding' || phase === 'detecting') return
    setExportMsg(null)
    searchMutation.mutate()
  }

  const handleExport = (format: 'json' | 'csv') => {
    if (!results.length) return
    const filename = `face-search-${Date.now()}.${format}`
    if (format === 'json') {
      const blob = new Blob([JSON.stringify({ results, generated_at: new Date().toISOString() }, null, 2)], {
        type: 'application/json',
      })
      download(blob, filename)
    } else {
      const header = 'match_id,title,source_url,similarity,confidence_category,source_type'
      const rows = results
        .map((r) =>
          [
            r.match_id,
            csv(r.title),
            csv(r.source_url),
            r.similarity.toFixed(4),
            r.confidence_category,
            csv(r.source_type),
          ].join(',')
        )
        .join('\n')
      const blob = new Blob([`${header}\n${rows}`], { type: 'text/csv' })
      download(blob, filename)
    }
    setExportMsg(`Exported ${results.length} result(s) to ${filename}`)
    setTimeout(() => setExportMsg(null), 5000)
  }

  function download(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  function csv(value: string): string {
    const s = String(value)
    return s.includes(',') || s.includes('"') ? `"${s.replace(/"/g, '""')}"` : s
  }

  function formatTime(ts: number): string {
    if (!Number.isFinite(ts)) return ''
    return new Date(ts * 1000).toLocaleTimeString()
  }

  const clearHistoryMutation = useMutation({
    mutationFn: async () => (await api.delete('/osint/face/history')).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['face-history'] }),
  })

  const { data: history } = useQuery({
    queryKey: ['face-history'],
    queryFn: async () => (await api.get('/osint/face/history')).data,
  })

  const canSearch = !!file && !['uploading', 'detecting', 'embedding', 'searching'].includes(phase)

  const filteredResults = sourceFilter ? results.filter((r) => (r.source_type || '') === sourceFilter) : results

  return (
    <div className="space-y-4 sm:space-y-5">
      <PageHeader
        title="Face Search"
        subtitle="Detect faces, generate embeddings, and search authorized/local face index"
        icon={<ScanFace className="w-8 h-8" />}
        color="cyan"
      >
        <div className="p-3 rounded-xl border border-cyan-500/20 bg-cyan-500/5 text-xs text-cyan-300/80">
          <ShieldAlert className="w-3.5 h-3.5 inline mr-1.5" />
          Face search returns similarity-based candidates from authorized or public sources. Results are
          not proof of identity. Verify findings with independent evidence.
        </div>
        <div className="flex flex-wrap gap-2 mt-3">
          <Button color="cyan" size="sm" variant="soft" onClick={() => setShowIndex((v) => !v)}>
            {showIndex ? 'Hide Index' : `Face Index (${indexData?.total ?? 0})`}
          </Button>
          <Button color="gray" size="sm" variant="soft" onClick={() => clearHistoryMutation.mutate()}>
            <History className="w-3.5 h-3.5 mr-1" /> Clear History
          </Button>
        </div>
      </PageHeader>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-5">
        <div className="lg:col-span-1 space-y-4">
          <FaceUpload
            onFile={(f) => {
              handleFile(f)
              detectMutation.mutate(f)
            }}
            previewUrl={previewUrl}
            onClear={handleClear}
            faces={faces}
            selectedFace={selectedFace}
            onSelectFace={setSelectedFace}
            disabled={phase === 'uploading' || phase === 'detecting'}
          />

          <Card className="border-cyan-500/20">
            <SectionHeader icon={<ScanFace className="w-4 h-4" />} title="Search Options" />
            <div className="mt-3 space-y-3">
              <label className="block">
                <span className="text-xs font-medium text-gray-400 block mb-1">Minimum similarity</span>
                <input
                  type="range"
                  min="0.5"
                  max="0.95"
                  step="0.01"
                  value={minSim}
                  onChange={(e) => setMinSim(parseFloat(e.target.value))}
                  className="w-full accent-cyan-500"
                />
                <span className="text-xs font-mono text-cyan-400">{minSim.toFixed(2)}</span>
              </label>
              <Select
                label="Source type filter"
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
              >
                <option value="">All source types</option>
                {FACE_SOURCE_TYPES.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </Select>
              <Button
                color="cyan"
                className="w-full"
                onClick={handleSearch}
                disabled={!canSearch}
              >
                <ScanFace className="w-4 h-4 mr-2" />
                {phase === 'uploading' || phase === 'detecting' || phase === 'embedding' || phase === 'searching'
                  ? 'Searching...'
                  : 'Search Face'}
              </Button>
            </div>
          </Card>

          <Card className="border-gray-800/40">
            <SectionHeader title="Provider" icon={<ScanFace className="w-4 h-4" />} />
            <div className="mt-2 text-sm">
              <div className="flex items-center justify-between mb-2">
                <span className="text-gray-400">Active provider</span>
                <span className="text-cyan-300 font-medium">
                  {(providers?.active || 'local').toUpperCase()}
                </span>
              </div>
              {(providers?.providers || []).map((p: { id: string; name: string; enabled: boolean; note?: string }) => (
                <div key={p.id} className="flex items-center gap-2 text-xs py-1.5 text-gray-400">
                  <span className={`w-2 h-2 rounded-full ${p.enabled ? 'bg-emerald-500' : 'bg-gray-600'}`} />
                  <span className="font-mono truncate">{p.name}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>

        <div className="lg:col-span-2 space-y-4">
          <FaceStatus phase={phase} />

          {error && (
            <InlineStatus status={phase === 'empty' ? 'warning' : 'error'}>
              {error}
            </InlineStatus>
          )}

          {phase === 'empty' && !error && (
            <EmptyState
              icon={<ScanFace className="w-8 h-8" />}
              title="No results"
              description="No candidates matched the minimum similarity threshold."
              action={
                <Button color="cyan" variant="soft" onClick={() => setMinSim(0.5)}>
                  Lower minimum similarity
                </Button>
              }
            />
          )}

          {showIndex && indexData && (
            <Card className="border-gray-800/40">
              <SectionHeader
                title={`Local Face Index (${indexData.total})`}
                icon={<ScanFace className="w-4 h-4" />}
              />
              <div className="mt-3 space-y-2 max-h-80 overflow-y-auto">
                {(indexData.entries || []).length === 0 && (
                  <div className="text-sm text-gray-500">Index is empty. Add authorized images to index.</div>
                )}
                {(indexData.entries || []).map((e: { id: string; title: string; source_url: string; source_type: string; created_at: number }) => (
                  <div key={e.id} className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-gray-800/40 border border-gray-800/40">
                    <div className="min-w-0">
                      <div className="text-sm text-gray-200 truncate">{e.title}</div>
                      <div className="text-[11px] text-gray-500 font-mono truncate">{e.source_url || 'no url'}</div>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-medium border border-gray-700/40 text-gray-400 shrink-0">
                      {e.source_type}
                    </span>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {results.length > 0 && (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <SectionHeader
                  icon={<ScanFace className="w-4 h-4" />}
                  title={`Candidates (${filteredResults.length})`}
                />
                <div className="flex gap-2">
                  <Button color="green" size="sm" variant="soft" onClick={() => handleExport('json')}>
                    <Download className="w-3.5 h-3.5 mr-1" /> JSON
                  </Button>
                  <Button color="green" size="sm" variant="soft" onClick={() => handleExport('csv')}>
                    <Download className="w-3.5 h-3.5 mr-1" /> CSV
                  </Button>
                </div>
              </div>
              {exportMsg && (
                <div className="text-xs text-emerald-400 bg-emerald-500/5 border border-emerald-500/20 rounded-lg px-3 py-2">
                  {exportMsg}
                </div>
              )}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {filteredResults.map((r) => (
                  <FaceResultCard key={r.match_id} result={r} onOpen={setDetail} />
                ))}
              </div>
            </>
          )}

          {history && history.history?.length > 0 && (
            <Card className="border-gray-800/40">
              <SectionHeader title="Recent Searches" icon={<History className="w-4 h-4" />} />
              <div className="mt-2 space-y-1.5">
                {history.history.map((h: FaceSearchHistoryEntry) => (
                  <div key={h.search_id} className="flex items-center justify-between text-xs text-gray-500 px-2 py-1.5 rounded-lg hover:bg-gray-800/40">
                    <span className="font-mono text-gray-400">{h.search_id}</span>
                    <span className="text-gray-600">{h.total} results · {formatTime(h.timestamp)}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      </div>

      <FaceResultDetail result={detail} onClose={() => setDetail(null)} />
    </div>
  )
}
