import { Check, Copy } from 'lucide-react'
import { useCopy } from '../../hooks/useCopy'
import { findingStatusStyles, jobStatusBadge, severityClass, severityClassBorder, severitySolid } from '../../utils/colors'

export function SeverityBadge({
  severity,
  variant = 'soft',
  size = 'sm',
  className = '',
}: {
  severity: string
  variant?: 'soft' | 'plain' | 'solid'
  size?: 'sm' | 'xs'
  className?: string
}) {
  const color =
    variant === 'solid'
      ? severitySolid[severity] || 'bg-gray-600'
      : variant === 'plain'
        ? severityClass[severity] || severityClass.MEDIUM
        : severityClassBorder[severity] || severityClassBorder.MEDIUM
  const base =
    size === 'xs'
      ? 'text-[10px] px-2 py-0.5 rounded font-bold text-white'
      : variant === 'plain'
        ? 'px-1.5 py-0.5 rounded text-xs font-medium'
        : 'px-1.5 py-0.5 rounded text-xs font-medium border'
  return <span className={`${base} ${color} ${className}`}>{severity}</span>
}

export function StatusBadge({
  status,
  variant = 'finding',
  className = '',
}: {
  status: string
  variant?: 'finding' | 'job'
  className?: string
}) {
  const styles = variant === 'job' ? jobStatusBadge : findingStatusStyles
  const s = styles[status]
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${s?.badge || ''} ${className}`}>
      {s?.label || status.toUpperCase()}
    </span>
  )
}

export function CopyButton({ text, className = '' }: { text: string; className?: string }) {
  const { copied, copy } = useCopy()
  return (
    <button
      onClick={() => copy(text)}
      className={`text-gray-600 hover:text-gray-300 ml-1 p-2 min-w-[44px] min-h-[44px] flex items-center justify-center ${className}`}
      title="Copy"
    >
      {copied ? <Check className="w-3 h-3 text-webforge-400" /> : <Copy className="w-3 h-3" />}
    </button>
  )
}
