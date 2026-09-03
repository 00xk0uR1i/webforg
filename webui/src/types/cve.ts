export interface CveEntry {
  id: string
  description: string
  cvss: number | null
  severity: string | null
  published: string | null
  cisa_kev: boolean
  vendor: string | null
  product: string | null
  exploit_available: boolean
}

export interface CveSearchResponse {
  cves: CveEntry[]
  count: number
}

export interface SploitusExploit {
  id: string
  title: string
  cve_id: string | null
  cvss: number | null
  published: string | null
  source_url: string | null
  source: string | null
  description: string
  code: string
  type: string
}

export interface SploitusSearchResponse {
  exploits: SploitusExploit[]
  count: number
}

export interface SploitusExploitDetail {
  id: string
  title: string
  cve_id: string | null
  cvss_score: number | null
  published_date: string | null
  source_url: string
  description: string
  raw_code: string
  exploit_type: string
}

export interface SploitusStats {
  total_exploits: number
  unique_cves: number
  by_type: Record<string, number>
  last_fetch: string | null
}

export interface SploitusRunFound {
  title: string
  cve: string
  cvss: number
  type: string
  severity: string
  rce: boolean
  method: string
}

export interface SploitusRunResult {
  success: boolean
  output: string
  found: SploitusRunFound[]
  error?: string
}
