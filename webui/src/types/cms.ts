export interface CmsHit {
  name: string
  severity: string
  cve: string
  rce: boolean
}

export interface CmsResult {
  success: boolean
  output: string
  hits: CmsHit[]
  error?: string
}

export interface CmsDetectResult {
  detected: boolean
  details: string
  extra: Record<string, unknown>
}
