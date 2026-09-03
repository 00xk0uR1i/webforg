export interface SecretFinding {
  type: string
  value: string
  url: string
  severity?: string
  cracked?: string
  decoded?: string
  hash_type?: string
  jwt_algorithm?: string
  jwt_header?: Record<string, string>
  jwt_payload?: Record<string, unknown>
  jwt_vulnerabilities?: string[]
  jwt_secrets?: string[]
  jwt_secret_cracked?: string
  branch?: string
}

export interface SecretScanResult {
  success?: boolean
  findings: SecretFinding[]
  total: number
  critical: number
  high: number
  cracked: number
}
