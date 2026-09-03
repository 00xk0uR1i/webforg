export interface OsintPlatform {
  id: string
  name: string
  category: string
}

export interface OsintPlatformGroup {
  categories: string[]
  count: number
  platforms: OsintPlatform[]
}

export interface OsintPlatformsResponse {
  username: OsintPlatformGroup
  email: OsintPlatformGroup
}

export interface OsintResult {
  platform: string
  name: string
  category: string
  status: 'found' | 'not_found' | 'error'
  url: string
  profile: Record<string, string | number>
  detail?: string
}

export interface OsintScanResponse {
  success: boolean
  query: string
  mode: string
  total: number
  found_count: number
  not_found_count: number
  error_count: number
  elapsed_ms: number
  categories: string[]
  results: OsintResult[]
}

export interface BreachStealer {
  stealer_family?: string | null
  os?: string | null
  date_compromised?: string | null
  computer_name?: string | null
  malware_path?: string | null
  ip?: string | null
  antiviruses: string[]
  top_logins: string[]
  top_passwords: string[]
  corporate_services: number
  user_services: number
}

export interface BreachItem {
  name?: string | null
  title?: string | null
  domain?: string | null
  breach_date?: string | null
  added_date?: string | null
  pwn_count?: number | null
  data_classes?: string[]
  description?: string | null
  verified?: boolean | null
  sensitive?: boolean | null
  date?: string | null
}

export interface BreachSource {
  id: string
  name: string
  enabled: boolean
  exposed: boolean
  error?: string | null
  stealers?: BreachStealer[]
  total_infections?: number
  total_corporate_services?: number
  total_user_services?: number
  breaches?: BreachItem[]
  leaked?: boolean
  reputation?: string | null
  suspicious?: boolean | null
  profiles?: number
}

export interface BreachResponse {
  success: boolean
  query: string
  mode: string
  exposed: boolean
  message?: string
  sources: BreachSource[]
  error?: string
}

export interface BreachProvider {
  id: string
  name: string
  enabled: boolean
  source: string
  modes: string[]
  key_needed?: string | null
}

export interface BreachSourcesResponse {
  providers: BreachProvider[]
}
