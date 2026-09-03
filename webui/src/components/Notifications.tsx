import { useState, useEffect, createContext, useContext, useCallback, type ReactNode } from 'react'
import clsx from 'clsx'

interface Toast {
  id: number
  message: string
  type: 'success' | 'error' | 'info'
}

interface ToastCtxType {
  toast: (msg: string, type?: Toast['type']) => void
}

const ToastCtx = createContext<ToastCtxType>({ toast: () => {} })

export const useToast = () => useContext(ToastCtx)

let nextId = 0

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])

  const addToast = useCallback((message: string, type: Toast['type'] = 'info') => {
    const id = ++nextId
    setToasts((prev) => [...prev, { id, message, type }])
  }, [])

  const removeToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  return (
    <ToastCtx.Provider value={{ toast: addToast }}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
        {toasts.map((t) => (
          <ToastItem key={t.id} toast={t} onDone={removeToast} />
        ))}
      </div>
    </ToastCtx.Provider>
  )
}

const toastStyles: Record<string, string> = {
  success: 'bg-green-900/90 border-green-700/50 text-green-300',
  error:   'bg-red-900/90 border-red-700/50 text-red-300',
  info:    'bg-blue-900/90 border-blue-700/50 text-blue-300',
}

function ToastItem({ toast, onDone }: { toast: Toast; onDone: (id: number) => void }) {
  const [visible, setVisible] = useState(false)
  useEffect(() => {
    requestAnimationFrame(() => setVisible(true))
    const timer = setTimeout(() => {
      setVisible(false)
      setTimeout(() => onDone(toast.id), 300)
    }, 4000)
    return () => clearTimeout(timer)
  }, [toast.id, onDone])

  return (
    <div
      role="alert"
      className={clsx(
        'pointer-events-auto border rounded-lg px-4 py-3 text-sm font-medium shadow-lg',
        'transition-all duration-300',
        toastStyles[toast.type],
        visible ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-4',
      )}
    >
      {toast.message}
    </div>
  )
}
