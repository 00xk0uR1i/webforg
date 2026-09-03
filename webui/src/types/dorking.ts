export interface DorkResult {
  title: string
  url: string
  snippet: string
  engine: string
}

export interface EngineStatus {
  status: 'ok' | 'error'
  count?: number
  message?: string
}

export interface DorkRunResponse {
  success: boolean
  query: string
  target: string | null
  engines: Record<string, EngineStatus>
  results: DorkResult[]
  total: number
  elapsed_ms: number
  error?: string
}

export interface Dork {
  name: string
  query: string
}

export interface DorkCategory {
  category: string
  icon: string
  dorks: Dork[]
}

export interface DorkLibraryResponse {
  categories: DorkCategory[]
}
