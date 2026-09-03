export type OsintFindingStatus = 'found' | 'not_found' | 'unknown' | 'error'

export interface OsintIdentityFinding {
  category: string
  item: string
  status: OsintFindingStatus
  detail?: string
  url?: string
}

export interface OsintIdentityRunResponse {
  success: boolean
  input: string
  vector: string
  findings: OsintIdentityFinding[]
  matches: number
}

export interface OsintUploadResponse {
  ok: boolean
  path: string
  dir: string
  filename: string
}

export interface OsintFaceFile {
  filename: string
  size: number
  path: string
}

export interface OsintFaceFilesResponse {
  dir: string
  files: OsintFaceFile[]
}
