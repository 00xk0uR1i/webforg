import { createContext, useContext, useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { Skull, Menu, X, Shield, Zap, Search, Database, Terminal, BookOpen, Bug, Target, Key, Users, Globe, Lock, Layout as LayoutIcon, Cpu, Eye, FolderOpen, ChevronDown, Crosshair, Brain, LogOut, Radar, Loader, Bomb, Fingerprint, ScanFace } from 'lucide-react'
import clsx from 'clsx'
import api from '../api'

interface SidebarContextType {
  open: boolean
  setOpen: (v: boolean) => void
  toggle: () => void
}

export const SidebarCtx = createContext<SidebarContextType>({ open: false, setOpen: () => {}, toggle: () => {} })

const navSections = [
  {
    title: 'ATTACK',
    items: [
      { to: '/scan', label: 'Auto Scan', icon: Zap, color: 'amber' },
      { to: '/portscan', label: 'Port Scanner', icon: Radar, color: 'amber' },
      { to: '/crawl', label: 'Form Crawler', icon: Search, color: 'amber' },
      { to: '/fuzz', label: 'WebFuzzer', icon: Crosshair, color: 'amber' },
      { to: '/auto-brute', label: 'Auto Brute', icon: Cpu, color: 'amber' },
      { to: '/bruteforce', label: 'Brute Force', icon: Lock, color: 'amber' },
      { to: '/spray', label: 'Password Spray', icon: Key, color: 'amber' },
      { to: '/enum', label: 'Account Enum', icon: Users, color: 'amber' },
      { to: '/creds', label: 'Cred Stuffing', icon: Database, color: 'amber' },
      { to: '/credvault', label: 'Cred Vault', icon: Key, color: 'amber' },
      { to: '/social', label: 'Social Phish', icon: Globe, color: 'amber' },
      { to: '/cms', label: 'CMS Exploit', icon: Bug, color: 'amber' },
      { to: '/sploitus-exploit', label: 'Sploitus Exploit', icon: Zap, color: 'amber' },
      { to: '/payloads', label: 'Payload Gen', icon: Bug, color: 'amber' },
    ],
  },
  {
    title: 'INTEL',
    items: [
      { to: '/cve', label: 'CVE Feed', icon: Shield, color: 'cyan' },
      { to: '/sploitus', label: 'Sploitus Scanner', icon: Crosshair, color: 'cyan' },
      { to: '/top10', label: 'OWASP Top 10', icon: BookOpen, color: 'cyan' },
      { to: '/secrets', label: 'Secret Scan', icon: Eye, color: 'cyan' },
      { to: '/dorking', label: 'Dorking', icon: Globe, color: 'cyan' },
      { to: '/osint', label: 'OSINT Identity', icon: Fingerprint, color: 'cyan' },
      { to: '/face-search', label: 'Face Search', icon: ScanFace, color: 'cyan' },
      { to: '/jobs', label: 'Job Center', icon: Loader, color: 'cyan' },
      { to: '/bugbounty', label: 'Bug Bounty', icon: Bomb, color: 'cyan' },
      { to: '/ai', label: 'AI Helper', icon: Brain, color: 'cyan' },
    ],
  },
  {
    title: 'MANAGE',
    items: [
      { to: '/', label: 'Dashboard', icon: LayoutIcon, color: 'webforge' },
      { to: '/modules', label: 'Modules', icon: Database, color: 'webforge' },
      { to: '/targets', label: 'Targets', icon: Target, color: 'webforge' },
      { to: '/sessions', label: 'Sessions', icon: Terminal, color: 'webforge' },
      { to: '/workspace', label: 'Workspace', icon: FolderOpen, color: 'webforge' },
    ],
  },
]

const itemColors: Record<string, string> = {
  red: 'text-red-400/70',
  amber: 'text-amber-400/70',
  green: 'text-green-400/70',
  blue: 'text-blue-400/70',
  yellow: 'text-yellow-400/70',
  purple: 'text-purple-400/70',
  cyan: 'text-cyan-400/70',
  webforge: 'text-webforge-400/70',
}

const activeColors: Record<string, string> = {
  amber: 'text-amber-400',
  cyan: 'text-cyan-400',
  webforge: 'text-webforge-400',
}

const activeBg: Record<string, string> = {
  amber: 'bg-amber-500/10',
  cyan: 'bg-cyan-500/10',
  webforge: 'bg-webforge-500/10',
}

export function Sidebar() {
  const { open, toggle } = useContext(SidebarCtx)
  const location = useLocation()
  const [expanded, setExpanded] = useState<Record<string, boolean>>({
    ATTACK: false,
    INTEL: false,
    MANAGE: true,
  })

  const toggleSection = (title: string) => {
    setExpanded((prev) => ({ ...prev, [title]: !prev[title] }))
  }

  const handleLogout = async () => {
    try {
      await api.post('/auth/logout')
    } catch {
      /* ignore */
    }
    window.dispatchEvent(new Event('auth:expired'))
  }

  const isSectionActive = (items: typeof navSections[0]['items']) =>
    items.some((item) => location.pathname === item.to || (item.to === '/' && location.pathname === '/'))

  return (
    <>
      {/* Mobile hamburger */}
      <button
        onClick={toggle}
        className={clsx(
          'fixed top-3 left-3 z-50 md:hidden p-3 min-w-[44px] min-h-[44px] flex items-center justify-center',
          'text-gray-400 hover:text-white rounded-lg bg-gray-900/90 border border-gray-800 shadow-lg transition-all',
          open && 'opacity-0 pointer-events-none',
        )}
        aria-label="Open menu"
      >
        <Menu className="w-5 h-5" />
      </button>

      {/* Mobile backdrop */}
      {open && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 md:hidden animate-fade-in"
          onClick={toggle}
          onKeyDown={(e) => e.key === 'Escape' && toggle()}
          role="button"
          tabIndex={-1}
          aria-label="Close menu"
        />
      )}

      {/* Sidebar */}
      <aside
        className={clsx(
          'fixed top-0 left-0 h-full bg-gray-900/95 border-r border-gray-800/60 z-50 flex flex-col',
          'transition-transform duration-200 w-60 backdrop-blur-md',
          'md:sticky md:h-screen md:translate-x-0',
          open ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
        )}
      >
        {/* Brand */}
        <div className="h-12 shrink-0 flex items-center gap-2.5 px-4 border-b border-gray-800/60">
          <Skull className="w-4.5 h-4.5 text-red-500 shrink-0" />
          <span className="font-bold text-webforge-400 text-sm tracking-wide">WebForge</span>
          <button
            onClick={toggle}
            className="ml-auto md:hidden p-2 text-gray-500 hover:text-gray-300 rounded-lg min-w-[36px] min-h-[36px] flex items-center justify-center transition-colors"
            aria-label="Close menu"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto overflow-x-hidden py-2">
          {navSections.map((section) => {
            const isExpanded = expanded[section.title]
            const active = isSectionActive(section.items)
            return (
              <div key={section.title} className="mb-1">
                <button
                  onClick={() => toggleSection(section.title)}
                  className={clsx(
                    'w-full flex items-center justify-between gap-2 px-4 text-[10px] font-bold uppercase tracking-widest min-h-[32px]',
                    'rounded-lg mx-1 transition-colors',
                    active ? 'text-gray-300' : 'text-gray-600 hover:text-gray-400',
                  )}
                  title={section.title}
                >
                  <span>{section.title}</span>
                  <ChevronDown className={clsx(
                    'w-3 h-3 transition-transform duration-200',
                    !isExpanded && '-rotate-90',
                  )} />
                </button>

                <div
                  className={clsx(
                    'overflow-hidden transition-all duration-200',
                    isExpanded ? 'max-h-[800px] opacity-100' : 'max-h-0 opacity-0',
                  )}
                >
                  <div className="space-y-0.5 mt-0.5 px-1">
                    {section.items.map(({ to, label, icon: Icon, color }) => {
                      const isActive = location.pathname === to || (to === '/' && location.pathname === '/')
                      return (
                        <NavLink
                          key={to}
                          to={to}
                          end={to === '/'}
                          onClick={() => { if (window.innerWidth < 768) toggle() }}
                          className={clsx(
                            'flex items-center gap-2.5 rounded-lg text-[13px] transition-all h-8 px-2.5',
                            isActive
                              ? [activeBg[color] || 'bg-gray-800', 'font-medium', activeColors[color] || 'text-gray-200']
                              : ['text-gray-500 hover:text-gray-300 hover:bg-gray-800/50'],
                          )}
                          title={label}
                        >
                          <Icon className={clsx(
                            'w-4 h-4 shrink-0 transition-colors',
                            isActive ? (activeColors[color] || 'text-gray-200') : (itemColors[color] || 'text-gray-600'),
                          )} />
                          <span className="truncate">{label}</span>
                        </NavLink>
                      )
                    })}
                  </div>
                </div>
              </div>
            )
          })}
        </nav>

        {/* Footer */}
        <div className="shrink-0 border-t border-gray-800/60">
          <div className="px-4 py-1.5 text-[10px] text-gray-700 text-center tracking-wide">v0.1.0</div>
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-2.5 px-4 h-10 min-h-[40px] text-[13px] text-gray-500 hover:text-red-400 hover:bg-red-500/5 transition-colors"
            title="Log Out"
          >
            <LogOut className="w-4 h-4 shrink-0" />
            <span className="truncate">Log Out</span>
          </button>
        </div>
      </aside>
    </>
  )
}
