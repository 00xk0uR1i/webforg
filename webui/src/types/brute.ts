export interface FoundCred {
  username: string
  password: string
  details?: string
  status?: string
  form_url?: string
}

export interface BruteForceResult {
  success: boolean
  found: FoundCred[]
  attempts: number
  lockout_detected: boolean
  elapsed?: number
  creds_saved?: number
  error?: string
}

export interface SprayResult {
  success: boolean
  found: FoundCred[]
  attempts?: number
  locked_users?: string[]
  elapsed?: number
  total?: number
  creds_saved?: number
  error?: string
}

export interface StuffResult {
  success: boolean
  found: FoundCred[]
  attempts?: number
  total?: number
  locked?: number
  total_creds?: number
  lockout_detected?: boolean
  elapsed?: number
  creds_saved?: number
  error?: string
}

export interface EnumUser {
  username: string
  reason: string
  avg_time: number
  diff: number
}

export interface EnumResult {
  success: boolean
  valid_users: EnumUser[]
  total_tested: number
  results: EnumUser[]
}

export interface AutoBruteResult {
  success: boolean
  found: FoundCred[]
  forms_tested: number
  session_id?: string
  error?: string
}
