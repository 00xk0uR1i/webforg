import { useEffect, useRef, useState } from 'react'
import { ImagePlus, RefreshCw, Upload, Trash2 } from 'lucide-react'
import { Button, Card } from '../UI'
import { DetectedFace } from '../../types/faceSearch'

interface FaceUploadProps {
  onFile: (file: File) => void
  previewUrl: string | null
  onClear: () => void
  faces: DetectedFace[]
  selectedFace: number
  onSelectFace: (faceId: number) => void
  disabled?: boolean
}

export function FaceUpload({
  onFile,
  previewUrl,
  onClear,
  faces,
  selectedFace,
  onSelectFace,
  disabled,
}: FaceUploadProps) {
  const [dragOver, setDragOver] = useState(false)
  const [fileName, setFileName] = useState<string | null>(null)
  const [fileSize, setFileSize] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement | null>(null)

  const handleFile = (file: File) => {
    if (!file || disabled) return
    setFileName(file.name)
    setFileSize(formatBytes(file.size))
    onFile(file)
  }

  useEffect(() => {
    if (!previewUrl) {
      setFileName(null)
      setFileSize(null)
    }
  }, [previewUrl])

  return (
    <Card className="border-webforge-500/20">
      <div className="flex flex-col md:flex-row gap-4">
        <div className="flex-1">
          <div
            onDragOver={(e) => {
              e.preventDefault()
              if (!disabled) setDragOver(true)
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault()
              setDragOver(false)
              const f = e.dataTransfer.files?.[0]
              if (f) handleFile(f)
            }}
            onClick={() => fileRef.current?.click()}
            className={[
              'flex flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed px-4 py-8 cursor-pointer transition-colors text-center',
              dragOver
                ? 'border-webforge-500 bg-webforge-500/5'
                : disabled
                  ? 'border-gray-800 bg-gray-900/20 cursor-not-allowed hover:border-gray-800'
                  : 'border-gray-700/60 bg-gray-900/20 hover:border-webforge-500/50 hover:bg-webforge-500/5',
            ].join(' ')}
          >
            <ImagePlus className="w-8 h-8 text-webforge-400" />
            <div className="text-sm text-gray-300 font-medium">Upload face image</div>
            <div className="text-xs text-gray-500">
              Drag &amp; drop or click to browse
            </div>
            <div className="text-[11px] text-gray-600">
              JPG, PNG or WebP &middot; max 10 MB
            </div>
          </div>
          <input
            ref={(el) => { fileRef.current = el }}
            type="file"
            accept="image/jpeg,image/png,image/webp,.jpg,.jpeg,.png,.webp"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) handleFile(f)
            }}
            aria-label="Upload face image"
          />
          {fileName && (
            <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
              <span className="px-2 py-1 rounded-lg bg-gray-800/60 border border-gray-700/40 text-gray-300 truncate max-w-full">
                <span className="text-gray-500">File:</span> {fileName}
              </span>
              {fileSize && (
                <span className="px-2 py-1 rounded-lg bg-gray-800/60 border border-gray-700/40 text-gray-400 font-mono">
                  {fileSize}
                </span>
              )}
              <button
                onClick={(e) => {
                  e.stopPropagation()
                  onClear()
                }}
                className="px-2 py-1 rounded-lg hover:bg-red-500/10 hover:text-red-400 text-gray-500 transition-colors"
                aria-label="Remove image"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>

        {previewUrl && (
          <div className="w-full md:w-48 shrink-0 flex flex-col items-center gap-2">
            <div className="relative w-40 h-40 rounded-xl overflow-hidden border border-gray-700/60 bg-gray-900">
              <img src={previewUrl} alt="Uploaded face preview" className="w-full h-full object-contain" />
            </div>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => fileRef.current?.click()}
                disabled={disabled}
                className="flex items-center gap-1 px-2 py-1 rounded-lg text-[11px] text-gray-400 hover:text-gray-200 hover:bg-gray-800 transition-colors disabled:opacity-50"
              >
                <RefreshCw className="w-3 h-3" /> Replace
              </button>
              <button
                onClick={onClear}
                className="flex items-center gap-1 px-2 py-1 rounded-lg text-[11px] text-gray-400 hover:text-red-400 hover:bg-red-500/10 transition-colors"
              >
                <Upload className="w-3 h-3" /> Clear
              </button>
            </div>
          </div>
        )}
      </div>

      {faces.length > 1 && (
        <div className="mt-4 border-t border-gray-800/60 pt-3">
          <div className="text-xs text-amber-400/80 mb-2">
            Multiple faces detected. Select a face to search.
          </div>
          <div className="flex flex-wrap gap-2">
            {faces.map((f) => (
              <button
                key={f.face_id}
                onClick={() => onSelectFace(f.face_id)}
                disabled={disabled}
                className={[
                  'px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors disabled:opacity-50',
                  selectedFace === f.face_id
                    ? 'border-webforge-500 bg-webforge-500/15 text-webforge-300'
                    : 'border-gray-700/40 bg-gray-800/40 text-gray-400 hover:border-gray-600 hover:text-gray-200',
                ].join(' ')}
              >
                Face {f.face_id + 1}
              </button>
            ))}
          </div>
        </div>
      )}
    </Card>
  )
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}
