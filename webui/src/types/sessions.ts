export interface SessionInfo {
  id: string
  target: string | null
  module_name: string
  payload_name: string
  session_type: string
  alive: boolean
  platform: string
  hostname: string
  username: string
  created_at: number
  last_active: number
  workspace?: string
}

export interface SessionListResponse {
  sessions: SessionInfo[]
}

export interface SendResponse {
  output: string
  alive: boolean
}

export interface SessionProbeResponse {
  session_type: string
  platform: string
}

export interface SessionUpgradeResponse {
  ok: boolean
  session_type: string
}

export interface SessionDownloadResponse {
  ok: boolean
  name: string
  size: number
  data_b64?: string
}

export interface SessionUploadResponse {
  ok: boolean
  path: string
  size: number
}

export interface SessionHashdumpResponse {
  ok: boolean
  passwd: string
  shadow: string
}

export interface SessionSysinfoResponse {
  ok: boolean
  uname: string
  os: string
  id: string
  pwd: string
  user: string
}

export interface CveFinding {
  cve: string
  name: string
  severity: string
  description: string
  status: string
  detail: string
}

export interface SessionCveScanResponse {
  ok: boolean
  summary: string
  vulnerable_count: number
  findings: CveFinding[]
}

export interface SessionCveExploitResponse {
  ok: boolean
  cve: string
  name: string
  note: string
  output: string
}

export interface ListenerInfo {
  name: string
  lhost: string
  lport: number
  payload_type: string
  running: boolean
}

export interface ListenerListResponse {
  listeners: ListenerInfo[]
}

export interface ListenerStartResponse {
  message: string
  name: string
}

export interface ListenerAgent {
  name: string
  lhost: string
  lport: number
  tls: boolean
  agent: string
}
