export interface CredRow {
  id: number
  target: string
  username: string
  password: string
  source: string
  extra: string
  created_at: number
}

export interface CredListResponse {
  creds: CredRow[]
  count: number
  total: number
}

export interface CredAddResponse {
  success: boolean
  added: boolean
  total: number
}

export interface CredDeleteResponse {
  success: boolean
}

export interface CredClearResponse {
  success: boolean
  removed: number
}
