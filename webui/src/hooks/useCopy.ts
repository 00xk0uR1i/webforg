import { useCallback, useEffect, useRef, useState } from 'react'

export function useCopy(timeoutMs = 1500) {
  const [copied, setCopied] = useState<string | null>(null)
  const timer = useRef<number | undefined>(undefined)

  useEffect(() => () => window.clearTimeout(timer.current), [])

  const copy = useCallback(
    async (text: string, key = 'copied') => {
      await navigator.clipboard.writeText(text)
      setCopied(key)
      window.clearTimeout(timer.current)
      timer.current = window.setTimeout(() => setCopied(null), timeoutMs)
    },
    [timeoutMs],
  )

  return { copied, copy }
}
