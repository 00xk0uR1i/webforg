export interface BbActionItem {
  value: string
  label: string
  cmd: string
}

export interface BbActionsResponse {
  actions: BbActionItem[]
  severities: string[]
}

export interface BbJobView {
  id: number
  label: string
  target: string
  done: boolean
  stopped: boolean
  code: number | null
  lines: number
  cmd: string
  start: string
  duration: number
}

export interface BbTargetFile {
  name: string
  size: number
  lines: number
}

export interface BbTargetInfo {
  name: string
  files: BbTargetFile[]
  report: boolean
}

export interface BbTargetsResponse {
  targets: BbTargetInfo[]
}

export interface BbTargetFileContent {
  name: string
  size: number
  lines: string[]
}

export interface BbTargetFilesResponse {
  target: string
  files: BbTargetFileContent[]
}

export interface BbStatusData {
  targets: number
  scans: number
  cve: number
  wordlists: number
  loot: number
  workspace: string
  active: boolean
}

export interface BbCveHit {
  cve: string
  target: string
  file: string
  vtype: string
  info: string
}

export interface BbCveSearchHit {
  id: string
  file: string
  severity: string
}

export interface BbRunResponse {
  id: number
  label: string
  saved: string
}

export interface BbRunExploitResponse {
  id: number
  label: string
  saved: string
}

export interface BbStopResponse {
  ok: boolean
  id: number
  label: string
}

export interface BbJobLog {
  id: number
  done: boolean
  code: number | null
  lines: string[]
}

export interface BbReportResponse {
  ok: boolean
  file: string
  findings: number
  markdown: string
}

export interface BbReportViewResponse {
  target: string
  markdown: string
}
