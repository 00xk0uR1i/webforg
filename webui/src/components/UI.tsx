import { ReactNode, InputHTMLAttributes, SelectHTMLAttributes, TextareaHTMLAttributes } from 'react'
import clsx from 'clsx'

/* ───────── Color Map ───────── */

const colorMap: Record<string, { bg: string; border: string; text: string; ring: string }> = {
  red:     { bg: 'bg-red-500/10',     border: 'border-red-500/25',     text: 'text-red-400',     ring: 'ring-red-500/40' },
  amber:   { bg: 'bg-amber-500/10',   border: 'border-amber-500/25',   text: 'text-amber-400',   ring: 'ring-amber-500/40' },
  orange:  { bg: 'bg-orange-500/10',  border: 'border-orange-500/25',  text: 'text-orange-400',  ring: 'ring-orange-500/40' },
  green:   { bg: 'bg-green-500/10',   border: 'border-green-500/25',   text: 'text-green-400',   ring: 'ring-green-500/40' },
  blue:    { bg: 'bg-blue-500/10',    border: 'border-blue-500/25',    text: 'text-blue-400',    ring: 'ring-blue-500/40' },
  cyan:    { bg: 'bg-cyan-500/10',    border: 'border-cyan-500/25',    text: 'text-cyan-400',    ring: 'ring-cyan-500/40' },
  purple:  { bg: 'bg-purple-500/10',  border: 'border-purple-500/25',  text: 'text-purple-400',  ring: 'ring-purple-500/40' },
  yellow:  { bg: 'bg-yellow-500/10',  border: 'border-yellow-500/25',  text: 'text-yellow-400',  ring: 'ring-yellow-500/40' },
  gray:    { bg: 'bg-gray-500/10',    border: 'border-gray-500/25',    text: 'text-gray-400',    ring: 'ring-gray-500/40' },
  webforge:{ bg: 'bg-webforge-500/10',border: 'border-webforge-500/25',text: 'text-webforge-400',ring: 'ring-webforge-500/40' },
}

/* ───────── PageHeader ───────── */

interface PageHeaderProps {
  title: string
  subtitle: string
  icon: ReactNode
  color?: string
  children?: ReactNode
}

export function PageHeader({ title, subtitle, icon, color = 'red', children }: PageHeaderProps) {
  const c = colorMap[color] || colorMap.red
  return (
    <div className="space-y-3 sm:space-y-4">
      <div className={clsx('flex items-center gap-3 px-4 py-3 rounded-xl border', c.bg, c.border)}>
        <div className={clsx('shrink-0', c.text)}>{icon}</div>
        <div className="min-w-0 flex-1">
          <h1 className={clsx('text-sm sm:text-base font-bold tracking-tight truncate', c.text)}>{title}</h1>
          <p className="text-gray-400 text-xs mt-0.5 line-clamp-2">{subtitle}</p>
        </div>
      </div>
      {children}
    </div>
  )
}

/* ───────── Card ───────── */

interface CardProps {
  children: ReactNode
  className?: string
  onClick?: () => void
}

export function Card({ children, className = '', onClick }: CardProps) {
  const clickable = !!onClick
  return (
    <div
      className={clsx(
        'surface-base rounded-xl p-4',
        clickable && 'card-interactive cursor-pointer',
        className,
      )}
      onClick={onClick}
      role={clickable ? 'button' : undefined}
      tabIndex={clickable ? 0 : undefined}
      onKeyDown={clickable ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick() } } : undefined}
    >
      {children}
    </div>
  )
}

/* ───────── Input ───────── */

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string
  hint?: string
}

let inputIdCounter = 0

export function Input({ label, hint, id, className = '', ...props }: InputProps) {
  const inputId = id || (label ? `input-${++inputIdCounter}` : undefined)
  return (
    <div>
      {label && <label htmlFor={inputId} className="input-label">{label}</label>}
      <input
        id={inputId}
        className={clsx(
          'w-full bg-gray-800/80 border border-gray-700/60 rounded-lg px-3 py-2.5 text-sm text-white placeholder-gray-500',
          'focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20',
          'transition-colors',
          className,
        )}
        {...props}
      />
      {hint && <p className="text-[11px] text-gray-500 mt-1">{hint}</p>}
    </div>
  )
}

/* ───────── Select ───────── */

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string
}

export function Select({ label, id, className = '', children, ...props }: SelectProps) {
  const selectId = id || (label ? `select-${++inputIdCounter}` : undefined)
  return (
    <div>
      {label && <label htmlFor={selectId} className="input-label">{label}</label>}
      <select
        id={selectId}
        className={clsx(
          'w-full bg-gray-800/80 border border-gray-700/60 rounded-lg px-3 py-2.5 text-sm text-white',
          'focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20',
          'transition-colors appearance-none',
          className,
        )}
        {...props}
      >
        {children}
      </select>
    </div>
  )
}

/* ───────── Textarea ───────── */

interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string
}

export function Textarea({ label, id, className = '', ...props }: TextareaProps) {
  const textareaId = id || (label ? `textarea-${++inputIdCounter}` : undefined)
  return (
    <div>
      {label && <label htmlFor={textareaId} className="input-label">{label}</label>}
      <textarea
        id={textareaId}
        className={clsx(
          'w-full bg-gray-800/80 border border-gray-700/60 rounded-lg px-3 py-2.5 text-sm text-white placeholder-gray-500',
          'focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20',
          'transition-colors resize-y',
          className,
        )}
        {...props}
      />
    </div>
  )
}

/* ───────── Button ───────── */

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  color?: string
  loading?: boolean
  variant?: 'solid' | 'soft' | 'ghost'
  size?: 'sm' | 'md' | 'lg'
}

const solidBg: Record<string, string> = {
  red:      'bg-red-600 hover:bg-red-500',
  amber:    'bg-amber-600 hover:bg-amber-500',
  orange:   'bg-orange-600 hover:bg-orange-500',
  green:    'bg-green-600 hover:bg-green-500',
  blue:     'bg-blue-600 hover:bg-blue-500',
  cyan:     'bg-cyan-600 hover:bg-cyan-500',
  purple:   'bg-purple-600 hover:bg-purple-500',
  yellow:   'bg-yellow-600 hover:bg-yellow-500',
  webforge: 'bg-webforge-600 hover:bg-webforge-500',
  gray:     'bg-gray-700 hover:bg-gray-600',
}

const softBg: Record<string, string> = {
  red:      'bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 text-red-400',
  amber:    'bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/20 text-amber-400',
  orange:   'bg-orange-500/10 hover:bg-orange-500/20 border border-orange-500/20 text-orange-400',
  green:    'bg-green-500/10 hover:bg-green-500/20 border border-green-500/20 text-green-400',
  blue:     'bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/20 text-blue-400',
  cyan:     'bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/20 text-cyan-400',
  purple:   'bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/20 text-purple-400',
  yellow:   'bg-yellow-500/10 hover:bg-yellow-500/20 border border-yellow-500/20 text-yellow-400',
  webforge: 'bg-webforge-500/10 hover:bg-webforge-500/20 border border-webforge-500/20 text-webforge-400',
  gray:     'bg-gray-700/50 hover:bg-gray-700 border border-gray-600/40 text-gray-300',
}

export function Button({ children, color = 'red', loading, variant = 'solid', size = 'md', className = '', disabled, ...props }: ButtonProps) {
  const bgClass = variant === 'solid' ? (solidBg[color] || solidBg.red) : variant === 'soft' ? (softBg[color] || softBg.red) : ''

  const sizeClass = size === 'sm'
    ? 'px-3 py-1.5 text-xs min-h-[32px]'
    : size === 'lg'
    ? 'px-5 py-3.5 text-sm min-h-[48px]'
    : 'px-4 py-2.5 text-sm min-h-[40px]'

  return (
    <button
      className={clsx(
        'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-all',
        sizeClass,
        bgClass,
        variant === 'ghost' && 'bg-transparent hover:bg-gray-800 text-gray-400 hover:text-gray-200',
        'disabled:opacity-50 disabled:cursor-not-allowed',
        className,
      )}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? (
        <>
          <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
          <span>Running...</span>
        </>
      ) : children}
    </button>
  )
}

/* ───────── Spinner ───────── */

export function Spinner({ text, color = 'webforge' }: { text: string; color?: string }) {
  const c = colorMap[color] || colorMap.webforge
  return (
    <div className={clsx('flex items-center gap-3 text-sm py-4', c.text)}>
      <div className={clsx('w-5 h-5 border-2 border-t-transparent rounded-full animate-spin', c.border, 'border-current')} />
      <span>{text}</span>
    </div>
  )
}

/* ───────── Stats ───────── */

interface StatItem {
  label: string
  value: string | number
  color?: string
  icon?: ReactNode
}

interface StatsProps {
  stats: StatItem[]
}

export function Stats({ stats }: StatsProps) {
  const cols =
    stats.length <= 2 ? 'grid-cols-2' :
    stats.length === 3 ? 'grid-cols-2 sm:grid-cols-3' :
    stats.length === 4 ? 'grid-cols-2 sm:grid-cols-2 lg:grid-cols-4' :
    'grid-cols-2 sm:grid-cols-3 xl:grid-cols-6'

  return (
    <div className={clsx('grid gap-3', cols)}>
      {stats.map((s, i) => {
        const c = colorMap[s.color || 'cyan']
        return (
          <div
            key={i}
            className={clsx(
              'rounded-xl border p-3.5 flex flex-col gap-2 min-h-[80px]',
              'bg-gray-900/40', c.border,
            )}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-[11px] font-medium uppercase tracking-wider text-gray-500 truncate">{s.label}</span>
              {s.icon && <span className={clsx('shrink-0 opacity-60', c.text)}>{s.icon}</span>}
            </div>
            <div className={clsx('text-xl font-bold leading-none tabular-nums', c.text)}>{s.value}</div>
          </div>
        )
      })}
    </div>
  )
}

/* ───────── Table ───────── */

interface TableProps {
  title?: string
  columns: string[]
  rows: (string | number | ReactNode)[][]
  color?: string
}

export function Table({ title, columns, rows, color = 'gray' }: TableProps) {
  const c = colorMap[color] || colorMap.gray
  return (
    <div className={clsx('rounded-xl border overflow-hidden', c.border, 'bg-gray-900/40')}>
      {title && (
        <div className={clsx('px-4 py-2.5 border-b', c.border, c.bg)}>
          <h3 className={clsx('font-semibold text-sm', c.text)}>{title}</h3>
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-xs sm:text-sm">
          <thead>
            <tr className="border-b border-gray-800/60">
              {columns.map((col) => (
                <th key={col} className="px-4 py-2.5 text-left text-gray-500 font-medium whitespace-nowrap uppercase tracking-wider text-[10px]">{col}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="px-4 py-8 text-center text-gray-600 text-sm">No data</td>
              </tr>
            ) : rows.map((row, i) => (
              <tr key={i} className="border-b border-gray-800/30 hover:bg-gray-800/20 transition-colors">
                {row.map((cell, j) => (
                  <td key={j} className="px-4 py-2.5">{cell}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/* ───────── EmptyState ───────── */

interface EmptyStateProps {
  icon?: ReactNode
  title: string
  description?: string
  action?: ReactNode
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      {icon && <div className="text-gray-700 mb-3">{icon}</div>}
      <h3 className="text-sm font-medium text-gray-400">{title}</h3>
      {description && <p className="text-xs text-gray-600 mt-1 max-w-sm">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

/* ───────── SectionHeader ───────── */

interface SectionHeaderProps {
  icon?: ReactNode
  title: string
  action?: ReactNode
}

export function SectionHeader({ icon, title, action }: SectionHeaderProps) {
  return (
    <div className="flex items-center justify-between gap-3">
      <div className="flex items-center gap-2">
        {icon && <div className="text-gray-500">{icon}</div>}
        <h3 className="text-sm font-semibold text-gray-300">{title}</h3>
      </div>
      {action}
    </div>
  )
}

/* ───────── SearchInput ───────── */

interface SearchInputProps {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  onSearch?: () => void
}

export function SearchInput({ value, onChange, placeholder = 'Search...', onSearch }: SearchInputProps) {
  return (
    <div className="relative">
      <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="11" cy="11" r="8" />
        <path d="m21 21-4.3-4.3" />
      </svg>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => e.key === 'Enter' && onSearch?.()}
        placeholder={placeholder}
        className={clsx(
          'w-full pl-10 pr-4 py-2.5 bg-gray-800/80 border border-gray-700/60 rounded-lg text-sm text-white placeholder-gray-500',
          'focus:border-webforge-500/60 focus:ring-1 focus:ring-webforge-500/20',
          'transition-colors',
        )}
      />
    </div>
  )
}

/* ───────── OutputBlock ───────── */

interface OutputBlockProps {
  title?: string
  children: ReactNode
  className?: string
  maxHeight?: string
}

export function OutputBlock({ title, children, className = '', maxHeight = 'max-h-64' }: OutputBlockProps) {
  return (
    <div className={clsx('rounded-xl border border-gray-800/50 overflow-hidden', className)}>
      {title && (
        <div className="px-3 py-2 border-b border-gray-800/50 bg-gray-900/50">
          <span className="text-[11px] font-medium text-gray-500 uppercase tracking-wider">{title}</span>
        </div>
      )}
      <pre className={clsx('output-block !rounded-none !border-0', maxHeight)}>
        {children}
      </pre>
    </div>
  )
}

/* ───────── Tabs ───────── */

interface Tab {
  id: string
  label: string
  icon?: ReactNode
}

interface TabBarProps {
  tabs: Tab[]
  active: string
  onChange: (id: string) => void
  color?: string
}

export function TabBar({ tabs, active, onChange, color = 'webforge' }: TabBarProps) {
  const c = colorMap[color] || colorMap.webforge
  return (
    <div className="flex gap-1 border-b border-gray-800/60 -mb-px overflow-x-auto">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          onClick={() => onChange(tab.id)}
          className={clsx(
            'flex items-center gap-2 px-3 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
            active === tab.id
              ? [c.border, c.text, 'border-b-current']
              : 'border-transparent text-gray-500 hover:text-gray-300 hover:border-gray-600',
          )}
        >
          {tab.icon}
          {tab.label}
        </button>
      ))}
    </div>
  )
}

/* ───────── CodeBlock ───────── */

export function CodeBlock({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <pre className={clsx('output-block text-green-400/90', className)}>
      {children}
    </pre>
  )
}

/* ───────── Modal ───────── */

interface ModalProps {
  open: boolean
  onClose: () => void
  title?: string
  children: ReactNode
  className?: string
}

export function Modal({ open, onClose, title, children, className = '' }: ModalProps) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 animate-fade-in" role="dialog" aria-modal="true">
      <div className="fixed inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className={clsx('relative bg-gray-900 border border-gray-700/60 rounded-2xl shadow-2xl max-w-lg w-full max-h-[80vh] flex flex-col animate-slide-up', className)}>
        {title && (
          <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800/60">
            <h3 className="text-sm font-semibold text-gray-200">{title}</h3>
            <button onClick={onClose} className="p-1 text-gray-500 hover:text-gray-300 rounded-lg hover:bg-gray-800 transition-colors" aria-label="Close">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M18 6 6 18" /><path d="m6 6 12 12" />
              </svg>
            </button>
          </div>
        )}
        <div className="flex-1 overflow-y-auto p-5">
          {children}
        </div>
      </div>
    </div>
  )
}

/* ───────── InlineStatus ───────── */

interface InlineStatusProps {
  status: 'success' | 'error' | 'warning' | 'info' | 'running'
  children: ReactNode
  className?: string
}

const statusStyles: Record<string, string> = {
  success: 'bg-green-500/10 border-green-500/20 text-green-400',
  error:   'bg-red-500/10 border-red-500/20 text-red-400',
  warning: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
  info:    'bg-blue-500/10 border-blue-500/20 text-blue-400',
  running: 'bg-cyan-500/10 border-cyan-500/20 text-cyan-400',
}

export function InlineStatus({ status, children, className = '' }: InlineStatusProps) {
  return (
    <div className={clsx('flex items-center gap-2 px-3 py-2 rounded-lg border text-sm', statusStyles[status], className)}>
      {status === 'running' && <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin shrink-0" />}
      {children}
    </div>
  )
}
