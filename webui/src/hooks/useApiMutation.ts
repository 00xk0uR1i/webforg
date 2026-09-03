import { useMutation } from '@tanstack/react-query'

export function useApiMutation<TVars, TData>(
  mutationFn: (vars: TVars) => Promise<TData>,
  onSuccess?: (data: TData, vars: TVars) => void,
) {
  return useMutation<TData, Error, TVars>({
    mutationFn,
    onSuccess,
  })
}
