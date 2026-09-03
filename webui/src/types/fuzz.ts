export interface FuzzDirectory {
  url: string
  status: number
  size: number
  redirect?: string
  note?: string
}

export interface FuzzEndpoint {
  method: string
  path: string
  params: Record<string, string>
}

export interface FuzzForm {
  action: string
  method: string
  params: string[]
}

export interface FuzzSpider {
  pages: number
  forms: FuzzForm[]
  endpoints: FuzzEndpoint[]
  param_count: number
}

export interface FuzzFinding {
  type: 'rce' | 'xss'
  severity: string
  url: string
  method: string
  param: string
  payload: string
  technique: string
  evidence: string
  confidence: string
  context?: string
  param_map?: Record<string, string>
}

export interface FuzzTotals {
  dirs: number
  soft404: number
  pages: number
  forms: number
  endpoints: number
  params: number
  rce: number
  xss: number
}

export interface FuzzResult {
  target: string
  server: string
  directories: FuzzDirectory[]
  spider: FuzzSpider
  findings: FuzzFinding[]
  totals: FuzzTotals
}
