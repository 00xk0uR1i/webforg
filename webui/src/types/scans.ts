export interface ScanResult {
  category: string
  check: string
  status: string
  details: string
}

export interface AutoScanResponse {
  success: boolean
  url: string
  results: ScanResult[]
  vuln_count: number
  elapsed: number
}

export interface PortResult {
  port: number
  state: string
  service: string
  product: string
  version: string
  banner: string
  ssl: boolean
}

export interface PortScanResponse {
  host: string
  ports_scanned: number
  ports_open: number
  duration: number
  results: PortResult[]
}
