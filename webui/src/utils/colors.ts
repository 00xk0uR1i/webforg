export const severityClass: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-400/10',
  HIGH: 'text-orange-400 bg-orange-400/10',
  MEDIUM: 'text-yellow-400 bg-yellow-400/10',
  LOW: 'text-blue-400 bg-blue-400/10',
}

export const severityClassBorder: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-400/10 border-red-400/30',
  HIGH: 'text-orange-400 bg-orange-400/10 border-orange-400/30',
  MEDIUM: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  LOW: 'text-cyan-400 bg-cyan-400/10 border-cyan-400/30',
}

export const severitySolid: Record<string, string> = {
  CRITICAL: 'bg-red-600',
  HIGH: 'bg-orange-600',
  MEDIUM: 'bg-yellow-600',
  LOW: 'bg-cyan-600',
}

export const severityLower: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400',
  high: 'bg-orange-500/15 text-orange-400',
  medium: 'bg-amber-500/15 text-amber-400',
  low: 'bg-blue-500/15 text-blue-400',
  info: 'bg-gray-500/15 text-gray-400',
  unknown: 'bg-gray-500/15 text-gray-400',
}

export const jobStatusBadge: Record<string, { badge: string; label: string }> = {
  queued: { badge: 'bg-gray-400/10 text-gray-400', label: 'QUEUED' },
  running: { badge: 'bg-blue-400/10 text-blue-400', label: 'RUNNING' },
  done: { badge: 'bg-green-400/10 text-green-400', label: 'DONE' },
  error: { badge: 'bg-red-400/10 text-red-400', label: 'ERROR' },
  cancelled: { badge: 'bg-amber-400/10 text-amber-400', label: 'CANCELLED' },
  cancelling: { badge: 'bg-amber-400/10 text-amber-400', label: 'CANCELLING' },
}

export const findingStatusStyles: Record<string, { badge: string; label: string }> = {
  found: { badge: 'bg-green-400/10 text-green-400', label: 'FOUND' },
  not_found: { badge: 'bg-gray-400/10 text-gray-500', label: 'NOT FOUND' },
  unknown: { badge: 'bg-amber-400/10 text-amber-400', label: 'UNKNOWN' },
  error: { badge: 'bg-red-400/10 text-red-400', label: 'ERROR' },
}

export const rankClass: Record<string, string> = {
  excellent: 'text-yellow-400 bg-yellow-400/10',
  great: 'text-orange-400 bg-orange-400/10',
  good: 'text-webforge-400 bg-webforge-400/10',
  normal: 'text-gray-400 bg-gray-400/10',
  low: 'text-red-400 bg-red-400/10',
}

export const exploitTypeClass: Record<string, string> = {
  metasploit: 'bg-red-400/10 text-red-400',
  python: 'bg-blue-400/10 text-blue-400',
  ruby: 'bg-orange-400/10 text-orange-400',
  shell: 'bg-green-400/10 text-green-400',
  php: 'bg-purple-400/10 text-purple-400',
  scanner: 'bg-cyan-400/10 text-cyan-400',
  java: 'bg-yellow-400/10 text-yellow-400',
  unknown: 'bg-gray-400/10 text-gray-400',
}

export function scanStatusClass(status: string): string {
  if (status === 'VULN' || status === 'CRITICAL') return 'text-red-400 font-bold'
  if (status === 'HIGH') return 'text-red-400'
  if (status === 'MEDIUM' || status === 'WARN') return 'text-yellow-400'
  if (status === 'LOW' || status === 'INFO') return 'text-cyan-400'
  if (status === 'SAFE') return 'text-green-400'
  return 'text-gray-400'
}
