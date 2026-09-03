import { type ReactNode } from 'react'
import clsx from 'clsx'

interface ConfirmDialogProps {
  open: boolean
  title: string
  message: string
  confirmLabel?: string
  cancelLabel?: string
  destructive?: boolean
  onConfirm: () => void
  onCancel: () => void
}

export function ConfirmDialog({ open, title, message, confirmLabel = 'Confirm', cancelLabel = 'Cancel', destructive = false, onConfirm, onCancel }: ConfirmDialogProps) {
  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 animate-fade-in" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
      <div className="fixed inset-0 bg-black/70 backdrop-blur-sm" onClick={onCancel} />
      <div className="relative bg-gray-900 border border-gray-700/60 rounded-2xl shadow-2xl max-w-md w-full p-6 animate-slide-up">
        <h3 id="confirm-title" className="text-base font-bold text-gray-100">{title}</h3>
        <p className="text-sm text-gray-400 mt-2 leading-relaxed">{message}</p>
        <div className="flex justify-end gap-3 mt-6">
          <button
            onClick={onCancel}
            className="px-4 py-2.5 min-h-[40px] bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-gray-300 hover:bg-gray-700 transition-colors"
          >
            {cancelLabel}
          </button>
          <button
            onClick={onConfirm}
            className={clsx(
              'px-4 py-2.5 min-h-[40px] rounded-lg text-sm font-medium text-white transition-colors',
              destructive ? 'bg-red-600 hover:bg-red-500' : 'bg-webforge-600 hover:bg-webforge-500',
            )}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}
