import { ExternalLink, User } from 'lucide-react'
import { Card, Modal } from '../UI'
import { FaceScore } from './FaceScore'
import { FaceSearchResult, FACE_CONFIDENCE_LABELS, FACE_SOURCE_TYPES } from '../../types/faceSearch'

interface FaceResultCardProps {
  result: FaceSearchResult
  onOpen: (result: FaceSearchResult) => void
}

export function FaceResultCard({ result, onOpen }: FaceResultCardProps) {
  const isLocal = result.source_type === 'local' || result.source_type === 'Authorized local corpus'
  return (
    <Card className="border-gray-700/40 card-interactive flex flex-col gap-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h4 className="text-sm font-semibold text-gray-200 truncate">{result.title || 'Untitled source'}</h4>
          <p className="mt-0.5 text-[11px] text-gray-500 truncate">
            {isLocal ? 'Authorized local corpus' : result.source_type || 'Public source'}
          </p>
        </div>
        <span className="px-2 py-0.5 rounded text-[10px] font-medium border border-webforge-500/20 bg-webforge-500/10 text-webforge-300 shrink-0">
          {FACE_CONFIDENCE_LABELS[result.confidence_category] || 'Candidate'}
        </span>
      </div>

      <FaceScore similarity={result.similarity} compact />

      {result.source_url && (
        <button
          onClick={() => onOpen(result)}
          className="flex items-center gap-1.5 text-xs text-webforge-400 hover:text-webforge-300 font-mono truncate transition-colors"
          aria-label={`Open source ${result.source_url}`}
        >
          <ExternalLink className="w-3 h-3 shrink-0" />
          <span className="truncate">{result.source_url}</span>
        </button>
      )}
    </Card>
  )
}

interface FaceResultDetailProps {
  result: FaceSearchResult | null
  onClose: () => void
}

export function FaceResultDetail({ result, onClose }: FaceResultDetailProps) {
  if (!result) return null
  const isLocal = result.source_type === 'local' || result.source_type === 'Authorized local corpus'

  return (
    <Modal open={!!result} onClose={onClose} title="Face Search Result" className="max-w-lg">
      <div className="space-y-4">
        <div className="flex items-center gap-4 flex-wrap">
          {result.metadata?.preview && typeof result.metadata.preview === 'string' ? (
            <img src={result.metadata.preview} alt="Matched thumbnail" className="w-20 h-20 rounded-lg object-cover border border-gray-700/60" />
          ) : (
            <div className="w-20 h-20 rounded-lg bg-gray-800/60 border border-gray-700/40 flex items-center justify-center text-gray-600">
              <User className="w-8 h-8" />
            </div>
          )}
          <div className="min-w-0 flex-1">
            <h4 className="text-base font-semibold text-gray-100 break-words">{result.title || 'Untitled source'}</h4>
            <p className="text-xs text-gray-500 mt-0.5">
              {isLocal ? 'Authorized local corpus' : result.source_type || 'Public source'}
            </p>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-gray-900/40 border border-gray-800/40 space-y-3">
          <FaceScore similarity={result.similarity} />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
          <div>
            <div className="text-[11px] text-gray-500 uppercase tracking-wider mb-1">Confidence</div>
            <div className="text-gray-200 font-medium">{FACE_CONFIDENCE_LABELS[result.confidence_category] || 'Candidate'}</div>
          </div>
          <div>
            <div className="text-[11px] text-gray-500 uppercase tracking-wider mb-1">Source type</div>
            <div className="text-gray-200">{result.source_type || 'Unknown'}</div>
          </div>
          {result.created_at && (
            <div>
              <div className="text-[11px] text-gray-500 uppercase tracking-wider mb-1">Indexed</div>
              <div className="text-gray-200 font-mono text-xs">{new Date(result.created_at * 1000).toLocaleString()}</div>
            </div>
          )}
          {typeof result.metadata?.filename === 'string' && result.metadata.filename && (
            <div>
              <div className="text-[11px] text-gray-500 uppercase tracking-wider mb-1">Filename</div>
              <div className="text-gray-200 font-mono text-xs truncate">{String(result.metadata.filename)}</div>
            </div>
          )}
        </div>

        {result.source_url && (
          <div>
            <div className="text-[11px] text-gray-500 uppercase tracking-wider mb-1">Source URL</div>
            <a
              href={safeUrl(result.source_url)}
              target="_blank"
              rel="noopener noreferrer"
              className="text-webforge-400 hover:text-webforge-300 font-mono text-xs break-all"
            >
              {result.source_url}
            </a>
          </div>
        )}

        <div className="p-3 rounded-lg border border-amber-500/20 bg-amber-500/5 text-xs text-amber-300/80">
          Face similarity is a lead, not proof of identity. Verify findings with independent evidence.
        </div>
      </div>
    </Modal>
  )
}

function safeUrl(url: string): string {
  try {
    const u = new URL(url)
    if (u.protocol === 'http:' || u.protocol === 'https:') return u.toString()
  } catch {
    /* ignore */
  }
  return '#'
}
