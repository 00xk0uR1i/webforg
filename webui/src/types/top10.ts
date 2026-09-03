export interface Technique {
  name: string
  description: string
  payloads: string[]
  detection_patterns: string[]
  evasion_tips: string[]
  tools: string[]
  references: string[]
}

export interface Top10ListItem {
  rank: number
  name: string
  owasp_id: string
  severity: string
  cvss_range: string
  description: string
  how_it_works: string
  impact: string
  techniques_count: number
  tools: string[]
  real_world_cves: string[]
}

export interface Top10ListResponse {
  vulns: Top10ListItem[]
}

export interface Top10Detail extends Omit<Top10ListItem, 'techniques_count'> {
  techniques: Technique[]
  remediation: string[]
  references: string[]
}

export interface Top10SearchResult {
  rank: number
  name: string
  owasp_id: string
  severity: string
  description: string
}

export interface Top10SearchResponse {
  vulns: Top10SearchResult[]
  count: number
}
