export interface DashboardModuleStats {
  total: number
  exploits: number
  auxiliary: number
  categories: Record<string, number>
}

export interface DashboardSession {
  id: string
  target: string | null
  module_name: string
  session_type: string
  created_at: number
}

export interface DashboardSessions {
  active: number
  sessions: DashboardSession[]
}

export interface DashboardCveExploits {
  total: number
  unique_cves: number
  by_type: Record<string, number>
  last_fetch: string | null
  top: DashboardCveExploit[]
}

export interface DashboardCveExploit {
  cve: string
  name: string
  cvss: number | null
  date: string | null
}

export interface DashboardData {
  modules: DashboardModuleStats
  sessions: DashboardSessions
  listeners: { active: number }
  cve_exploits: DashboardCveExploits
  owasp_top10: { total: number }
}
