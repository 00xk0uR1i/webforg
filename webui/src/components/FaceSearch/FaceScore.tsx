import clsx from 'clsx'
import { FACE_CONFIDENCE_COLORS, FACE_CONFIDENCE_LABELS } from '../../types/faceSearch'

export function FaceScore({
  similarity,
  compact = false,
}: {
  similarity: number
  compact?: boolean
}) {
  const pct = Math.round(similarity * 100)
  const category = categorize(similarity)

  return (
    <div className={compact ? 'w-full' : 'w-full'}>
      <div className="flex items-center justify-between mb-1">
        <span className={clsx('text-xs font-semibold', compact ? 'text-gray-400' : 'text-gray-300')}>
          Similarity
        </span>
        <span className="text-sm font-bold text-gray-100 font-mono">{pct}%</span>
      </div>
      <div className="h-1.5 w-full bg-gray-800/60 rounded-full overflow-hidden">
        <div
          className={clsx('h-full rounded-full transition-all', barColor(category))}
          style={{ width: `${Math.min(100, pct)}%` }}
        />
      </div>
      <div className={clsx('mt-1.5 inline-flex items-center px-2 py-0.5 rounded border text-[11px] font-medium', FACE_CONFIDENCE_COLORS[category] || 'text-gray-400 bg-gray-800/60 border-gray-700')}>
        {FACE_CONFIDENCE_LABELS[category] || 'Candidate match'}
      </div>
    </div>
  )
}

function categorize(similarity: number): string {
  if (similarity >= 0.9) return 'very_strong'
  if (similarity >= 0.83) return 'strong'
  if (similarity >= 0.7) return 'possible'
  if (similarity >= 0.5) return 'weak'
  return 'below_threshold'
}

function barColor(category: string): string {
  switch (category) {
    case 'very_strong':
      return 'bg-emerald-500'
    case 'strong':
      return 'bg-green-500'
    case 'possible':
      return 'bg-amber-500'
    case 'weak':
      return 'bg-gray-500'
    default:
      return 'bg-gray-700'
  }
}
