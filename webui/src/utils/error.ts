interface ErrorLike {
  userMessage?: string
  message?: string
  response?: { data?: { detail?: unknown } }
}

export function getErrorMessage(err: unknown): string {
  const e = (err ?? {}) as ErrorLike
  const detail = e.userMessage ?? e.response?.data?.detail
  if (typeof detail === 'string' && detail) return detail
  if (Array.isArray(detail) && detail.length) {
    const first = detail[0] as { loc?: (string | number)[]; msg?: string } | undefined
    const loc = first?.loc?.join('.')
    return loc ? `${loc}: ${first?.msg}` : first?.msg || e.message || 'Unknown error'
  }
  return e.message || 'Unknown error'
}
