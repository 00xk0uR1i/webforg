import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Boxes, Crosshair, Bug, Shield, Terminal, Radio, Zap, Search, Lock, Globe, BookOpen, Target, Activity, ChevronRight } from 'lucide-react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import api from '../api'
import { Card, Stats, Spinner } from '../components/UI'
import type { DashboardData } from '../types'

const TOOLTIP_STYLE = { background: '#1f2937', border: '1px solid #374151', borderRadius: '8px', fontSize: '12px' }
const TOOLTIP_ITEM = { color: '#e5e7eb' }

const MODULE_PIE_COLORS = ['#f59e0b', '#06b6d4']
const CHART_COLORS = ['#06b6d4', '#f59e0b', '#22c55e', '#8b5cf6', '#3b82f6', '#e879f9', '#14b8a6', '#a3e635']

const quickActions = [
  { to: '/scan', label: 'Auto Scan', desc: 'Full recon & exploitation', icon: Zap, color: 'text-amber-400' },
  { to: '/secrets', label: 'Secret Scan', desc: '12-phase data discovery', icon: Search, color: 'text-amber-400' },
  { to: '/bruteforce', label: 'Brute Force', desc: 'Login brute force', icon: Lock, color: 'text-amber-400' },
  { to: '/social', label: 'Social Auth', desc: '16 platform tests', icon: Globe, color: 'text-amber-400' },
  { to: '/cve', label: 'CVE Feed', desc: 'Live exploit database', icon: Shield, color: 'text-cyan-400' },
  { to: '/cms', label: 'CMS Exploit', desc: 'WordPress, Joomla, Drupal...', icon: Bug, color: 'text-amber-400' },
  { to: '/top10', label: 'OWASP Top 10', desc: 'Attack reference guides', icon: BookOpen, color: 'text-cyan-400' },
  { to: '/crawl', label: 'Form Crawler', desc: 'Discover login forms', icon: Target, color: 'text-cyan-400' },
]

export default function Dashboard() {
  const { data, isLoading } = useQuery<DashboardData>({
    queryKey: ['dashboard'],
    queryFn: async () => {
      const res = await api.get<DashboardData>('/dashboard')
      return res.data
    },
  })

  const [greeting, setGreeting] = useState('')
  useEffect(() => {
    const h = new Date().getHours()
    if (h < 12) setGreeting('Good morning')
    else if (h < 18) setGreeting('Good afternoon')
    else setGreeting('Good evening')
  }, [])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner text="Loading dashboard..." />
      </div>
    )
  }

  if (!data) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-sm text-red-400">Failed to load dashboard. Is the backend running?</div>
      </div>
    )
  }

  const modulePieData = [
    { name: 'Exploits', value: data.modules.exploits },
    { name: 'Auxiliary', value: data.modules.auxiliary },
  ]

  const categoryBarData = Object.entries(data.modules.categories)
    .map(([name, count]) => ({ name: name.charAt(0).toUpperCase() + name.slice(1), count }))
    .sort((a, b) => b.count - a.count)

  const exploitTypeData = Object.entries(data.cve_exploits.by_type)
    .map(([name, count]) => ({ name: name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()), count }))
    .sort((a, b) => b.count - a.count)
  const exploitTypeShown = exploitTypeData.slice(0, 8)

  const moduleTotal = data.modules.total || 1

  return (
    <div className="space-y-5">
      {/* Header */}
      <header className="relative overflow-hidden rounded-xl border border-gray-800/40 bg-gray-900/40 px-5 py-4 flex items-center gap-4">
        <div className="absolute top-0 right-0 w-44 h-44 bg-webforge-500/5 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2 pointer-events-none" />
        <img src="/logo.svg" alt="WebForge" className="w-10 h-10 shrink-0" />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h1 className="text-base sm:text-lg font-bold text-white truncate">WebForge</h1>
            <span className="text-[9px] sm:text-[10px] font-bold uppercase tracking-widest text-webforge-400 bg-webforge-500/10 border border-webforge-500/20 rounded px-1.5 py-0.5 shrink-0">
              Command Center
            </span>
          </div>
          <p className="text-[11px] sm:text-xs text-gray-500 mt-0.5 truncate">
            {greeting}, Operator — {data.modules.total} modules &middot; {data.cve_exploits.unique_cves} unique CVEs
            &middot; {data.sessions.active} sessions &middot; {data.owasp_top10.total} OWASP guides
          </p>
        </div>
        <div className="hidden lg:flex items-center gap-4 text-[11px] text-gray-500 shrink-0">
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-cyan-400" />{data.modules.total} modules</span>
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-amber-400" />{data.cve_exploits.unique_cves} CVEs</span>
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-cyan-400" />{data.sessions.active} sessions</span>
        </div>
      </header>

      {/* Stats */}
      <Stats stats={[
        { label: 'Total Modules', value: data.modules.total, color: 'cyan', icon: <Boxes className="w-4 h-4" /> },
        { label: 'Exploit Modules', value: data.modules.exploits, color: 'amber', icon: <Crosshair className="w-4 h-4" /> },
        { label: 'CVE Exploits', value: data.cve_exploits.total, color: 'amber', icon: <Bug className="w-4 h-4" /> },
        { label: 'Unique CVEs', value: data.cve_exploits.unique_cves, color: 'cyan', icon: <Shield className="w-4 h-4" /> },
        { label: 'Active Sessions', value: data.sessions.active, color: 'green', icon: <Terminal className="w-4 h-4" /> },
        { label: 'Listeners', value: data.listeners.active, color: 'blue', icon: <Radio className="w-4 h-4" /> },
      ]} />

      {/* Charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <Card>
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Module Distribution</h3>
          <div className="h-44 sm:h-48">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={modulePieData} cx="50%" cy="50%" innerRadius={48} outerRadius={78} paddingAngle={4} dataKey="value" stroke="transparent">
                  {modulePieData.map((_, i) => <Cell key={i} fill={MODULE_PIE_COLORS[i]} />)}
                </Pie>
                <Tooltip contentStyle={TOOLTIP_STYLE} itemStyle={TOOLTIP_ITEM} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex justify-center gap-5 mt-2">
            {modulePieData.map((d, i) => {
              const pct = Math.round((d.value / moduleTotal) * 100)
              return (
                <div key={d.name} className="flex items-center gap-2 text-xs">
                  <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ background: MODULE_PIE_COLORS[i] }} />
                  <span className="text-gray-300 font-medium">{d.name}</span>
                  <span className="text-gray-500">{d.value} &middot; {pct}%</span>
                </div>
              )
            })}
          </div>
        </Card>

        <Card>
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Modules by Category</h3>
          <div className="h-44 sm:h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoryBarData} layout="vertical" margin={{ left: 10, right: 10 }}>
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="name" width={80} tick={{ fill: '#9ca3af', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={20}>
                  {categoryBarData.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
                </Bar>
                <Tooltip contentStyle={TOOLTIP_STYLE} itemStyle={TOOLTIP_ITEM} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card>
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">CVE Exploit Types</h3>
          {exploitTypeShown.length === 0 ? (
            <div className="h-44 sm:h-48 flex items-center justify-center text-xs text-gray-600">No exploit data yet</div>
          ) : (
            <>
              <div className="h-44 sm:h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={exploitTypeShown} layout="vertical" margin={{ left: 10, right: 10 }}>
                    <XAxis type="number" hide />
                    <YAxis type="category" dataKey="name" width={90} tick={{ fill: '#9ca3af', fontSize: 10 }} axisLine={false} tickLine={false} />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={20}>
                      {exploitTypeShown.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
                    </Bar>
                    <Tooltip contentStyle={TOOLTIP_STYLE} itemStyle={TOOLTIP_ITEM} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="flex flex-wrap justify-center gap-x-4 gap-y-1 mt-2">
                {exploitTypeShown.map((d, i) => (
                  <div key={d.name} className="flex items-center gap-1.5 text-[10px]">
                    <span className="w-2 h-2 rounded-sm shrink-0" style={{ background: CHART_COLORS[i % CHART_COLORS.length] }} />
                    <span className="text-gray-400 font-medium truncate">{d.name}</span>
                    <span className="text-gray-600">{d.count}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </Card>
      </div>

      {/* Quick Actions + Recent CVEs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Quick Actions</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {quickActions.map((action) => (
              <Link
                key={action.to}
                to={action.to}
                className="flex items-center gap-3 p-3 rounded-lg bg-gray-800/30 hover:bg-gray-800/60 border border-gray-800/40 hover:border-gray-700/60 transition-all group min-h-[44px]"
              >
                <action.icon className={`w-4 h-4 shrink-0 ${action.color} opacity-70 group-hover:opacity-100`} />
                <div className="min-w-0 flex-1">
                  <div className="text-xs font-medium text-gray-300 group-hover:text-white truncate">{action.label}</div>
                  <div className="text-[10px] text-gray-600 truncate">{action.desc}</div>
                </div>
                <ChevronRight className="w-3 h-3 text-gray-700 group-hover:text-gray-500 shrink-0" />
              </Link>
            ))}
          </div>
        </Card>

        <Card>
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Top CVE Exploits</h3>
            <Link to="/cve" className="text-[11px] text-webforge-400 hover:text-webforge-300 flex items-center gap-1 transition-colors">
              View all <ChevronRight className="w-3 h-3" />
            </Link>
          </div>
          {data.cve_exploits.top.length === 0 ? (
            <div className="text-center py-8 text-xs text-gray-600">No CVE exploits loaded yet</div>
          ) : (
            <div className="space-y-1 max-h-[320px] overflow-y-auto">
              {data.cve_exploits.top.slice(0, 10).map((exploit, i) => {
                const cvss = exploit.cvss || 0
                const cvssColor = cvss >= 9 ? 'text-red-400' : cvss >= 7 ? 'text-orange-400' : cvss >= 4 ? 'text-yellow-400' : 'text-gray-400'
                return (
                  <div key={i} className="flex items-center gap-3 p-2.5 rounded-lg bg-gray-800/20 border border-gray-800/30 hover:border-gray-700/50 transition-colors">
                    <div className={`w-10 text-center font-mono text-xs font-bold ${cvssColor}`}>
                      {cvss > 0 ? cvss.toFixed(1) : '\u2014'}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-medium text-gray-200 truncate">{exploit.name}</div>
                      <div className="text-[10px] text-gray-500 font-mono">{exploit.cve}</div>
                    </div>
                    {exploit.date && (
                      <div className="text-[10px] text-gray-600 shrink-0">{exploit.date}</div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </Card>
      </div>

      {/* Active Sessions */}
      {data.sessions.active > 0 && (
        <Card>
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400/70" />
              Active Sessions
            </h3>
            <Link to="/sessions" className="text-[11px] text-webforge-400 hover:text-webforge-300 flex items-center gap-1 transition-colors">
              Manage <ChevronRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="space-y-1">
            {data.sessions.sessions.map((s) => (
              <div key={s.id} className="flex items-center gap-3 p-2.5 rounded-lg bg-gray-800/20 border border-gray-800/30">
                <div className={`status-dot ${s.session_type === 'meterpreter' ? 'bg-green-400' : 'bg-yellow-400'}`} />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-gray-200 truncate">{s.target || 'Unknown'}</div>
                  <div className="text-[10px] text-gray-500">{s.session_type} &middot; {s.module_name}</div>
                </div>
                <div className="text-[10px] text-gray-600 shrink-0 font-mono">{s.id.substring(0, 8)}</div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
