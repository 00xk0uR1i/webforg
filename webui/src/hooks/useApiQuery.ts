import { useQuery } from '@tanstack/react-query'

export function useApiQuery<TData>(
  key: string[],
  queryFn: () => Promise<TData>,
  options: { enabled?: boolean; refetchInterval?: number | false } = {},
) {
  return useQuery<TData>({ queryKey: key, queryFn, ...options })
}
