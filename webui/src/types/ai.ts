export interface LlmStatus {
  configured: boolean
  model: string | null
  mode: string
}

export interface AiRelatedFinding {
  id: string
  label: string
  severity: string
}

export interface AiChatResult {
  success: boolean
  answer: string
  related_findings: AiRelatedFinding[]
  llm?: boolean
  model?: string
  mode?: string
}

export interface AiFinding {
  id: string
  label: string
  severity: string
  description: string
  poc: string
  module: string
  remediation: string
  cwe: string
  match_score: number
}

export interface AiAnalysisSummary {
  total_findings: number
  severity_breakdown: Record<string, number>
}

export interface AiAnalysisResult {
  success: boolean
  findings: AiFinding[]
  summary: AiAnalysisSummary
  formats_detected: string[]
  llm: LlmStatus
  ai_insights?: string
}

export interface AiExploitResult {
  success: boolean
  vulnerability: string
  target: string
  module_used: string
  poc_generated: string
  remediation?: string
  execution_result: Record<string, unknown> | null
}

export interface CvePocGithubSource {
  count: number
  url?: string | null
  pocs: Array<{
    name?: string
    html_url?: string
    description?: string
    stargazers?: number
    forks?: number
    created_at?: string
  }>
}

export interface CvePocOtherSource {
  metasploit?: { module: string; rank?: string; command: string; url?: string }
  exploitdb?: { file: string; command: string; url?: string }
  nuclei?: { template?: string; command: string; url?: string }
}

export interface CvePocResult {
  cve_id: string
  success: boolean
  error?: string
  state?: string
  partial?: boolean
  errors?: string[]
  severity?: string
  cvss_score?: string
  epss_score?: string
  kev?: string
  kev_notes?: string
  description?: string
  remediation?: string
  rejected_reason?: string
  cwe?: string[]
  publication_date?: string
  vendor?: string
  affected_product?: string
  vector_string?: string
  sources?: {
    github?: CvePocGithubSource
    metasploit_exploitdb_nuclei?: CvePocOtherSource
    bug_bounty?: Array<{ source: string; poc_available?: string; url: string }>
    labs?: { htb?: string; thm?: string; docker_vulhub?: string }
  }
}
