export interface Module {
  path: string
  name: string
  description: string
  type: string
  rank: string
  cve?: string
  cvss?: number
}

export interface ModuleOption {
  value: unknown
  type: string
  required: boolean
  description: string
}

export interface ModuleInfo extends Module {
  author: string
  disclosure_date?: string
  options: Record<string, ModuleOption>
}

export interface ModuleListResponse {
  modules: Module[]
}

export interface SetOptionResponse {
  ok: boolean
}

export interface ModuleCheckResult {
  vulnerable: boolean
  details: string
}

export interface ModuleExploitResponse {
  success: boolean
  output: string
  session_id?: string
}
