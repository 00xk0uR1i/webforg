export interface TargetFingerprint {
  server?: string
  technologies?: string[]
  [key: string]: unknown
}

export interface WorkspaceTarget {
  host: string
  port: number
  ssl: boolean
  path: string
  fingerprint?: TargetFingerprint
}

export interface WorkspaceData {
  targets: WorkspaceTarget[]
  results: Record<string, unknown>[]
  name: string
}

export interface WorkspacesResponse {
  workspaces: string[]
}

export interface WorkspaceLoadResponse extends WorkspaceData {
  loaded: boolean
}
