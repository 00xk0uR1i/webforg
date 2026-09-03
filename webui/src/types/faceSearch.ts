export interface FaceBoundingBox {
  x: number
  y: number
  w: number
  h: number
  confidence: number
}

export interface DetectedFace {
  face_id: number
  bounding_box: FaceBoundingBox
  confidence: number
}

export interface FaceDetectionResponse {
  faces?: DetectedFace[]
  image_width?: number
  image_height?: number
  message?: string
  error?: string
}

export interface FaceSearchResult {
  match_id: string
  similarity: number
  confidence_category: string
  source_url: string
  title: string
  source_type: string
  metadata: Record<string, unknown>
  created_at?: number
}

export interface FaceSearchResponse {
  results: FaceSearchResult[]
  total: number
  message?: string
  error?: string
}

export interface FaceProvider {
  id: string
  name: string
  enabled: boolean
  note?: string
}

export interface FaceProviderResponse {
  providers: FaceProvider[]
  active: string
}

export interface FaceIndexEntry {
  id: string
  title: string
  source_url: string
  source_type: string
  created_at: number
}

export interface FaceIndexResponse {
  entries: FaceIndexEntry[]
  total: number
}

export interface FaceSearchHistoryEntry {
  search_id: string
  total: number
  timestamp: number
}

export type FaceSearchPhase =
  | 'idle'
  | 'uploading'
  | 'detecting'
  | 'face-selection'
  | 'embedding'
  | 'searching'
  | 'results'
  | 'empty'
  | 'error'

export const FACE_CONFIDENCE_LABELS: Record<string, string> = {
  very_strong: 'Very strong candidate',
  strong: 'Strong candidate',
  possible: 'Possible candidate',
  weak: 'Weak candidate',
  below_threshold: 'Below threshold',
}

export const FACE_CONFIDENCE_COLORS: Record<string, string> = {
  very_strong: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  strong: 'text-green-400 bg-green-500/10 border-green-500/20',
  possible: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  weak: 'text-gray-400 bg-gray-500/10 border-gray-500/20',
  below_threshold: 'text-gray-500 bg-gray-500/5 border-gray-500/20',
}

export const FACE_SOURCE_TYPES = [
  'Social profile',
  'News',
  'Blog',
  'Forum',
  'Organization',
  'Public website',
  'Authorized local corpus',
  'CTF/Lab',
  'local',
]

export interface IndexedImageInput {
  file: File
  source_url?: string
  title?: string
  source_type?: string
}
