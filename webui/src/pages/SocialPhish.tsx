import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { Globe, Play, Square, Copy, Check, MessageSquare, Mail, Link2, Rocket, AlertTriangle, Terminal, Save, Trash2 } from 'lucide-react'
import clsx from 'clsx'
import api from '../api'
import { PageHeader, Card, Button, SectionHeader } from '../components/UI'
import { useCopy } from '../hooks/useCopy'
import type {
  TunnelInfo,
  TunnelStatusData,
  TunnelStartResponse,
  TunnelStopResponse,
  TunnelManualResponse,
  PhishTemplate,
  PhishTemplatesResponse,
  RenderedTemplate,
} from '../types'

const toolLabels: Record<string, string> = {
  ssh: 'SSH Reverse',
}

const VARIABLE_LABELS: Record<string, string> = {
  first_name: 'First name',
  last_name: 'Last name',
  email: 'Email',
  company: 'Company',
  platform: 'Platform',
  link: 'Phishing link',
  expiry: 'Expiry',
  sender: 'Sender',
  reference: 'Reference ID',
  amount: 'Amount',
  code: 'Code',
  last4: 'Card last 4 digits',
  merchant: 'Merchant',
  bank: 'Bank name',
  telecom: 'Telecom provider',
  tracking: 'Tracking number',
  order: 'Order ID',
  document: 'Document name',
  filename: 'Filename',
  location: 'Location',
  device: 'Device',
  count: 'Search count',
  date: 'Date',
  time: 'Time',
  health: 'Health provider',
}

export default function SocialPhish() {
  const [port, setPort] = useState('8080')
  const [remote, setRemote] = useState('')
  const [remotePort, setRemotePort] = useState('80')
  const [publicUrlInput, setPublicUrlInput] = useState('')
  const [kind, setKind] = useState<'sms' | 'email'>('sms')
  const [templateId, setTemplateId] = useState('')
  const [vars, setVars] = useState<Record<string, string>>({})
  const [rendered, setRendered] = useState<RenderedTemplate | null>(null)
  const [previewMode, setPreviewMode] = useState<'html' | 'plain'>('html')
  const { copy, copied } = useCopy(2000)
  const [manualMsg, setManualMsg] = useState<{ ok: boolean; text: string } | null>(null)

  const { data: statusData, refetch: refetchStatus } = useQuery({
    queryKey: ['phish-tunnel-status'],
    queryFn: async () => {
      const res = await api.get<TunnelStatusData>('/phish/tunnel/status')
      return res.data
    },
    refetchInterval: 8000,
  })

  const manualUrl = statusData?.manual_url || ''
  const ssh = statusData?.tunnels.ssh || { tool: 'ssh', installed: false, running: false, url: null, port: null, pid: null, started_at: null, help: '' }

  const { data: templatesData } = useQuery({
    queryKey: ['phish-templates'],
    queryFn: async () => {
      const res = await api.get<PhishTemplatesResponse>('/phish/templates')
      return res.data
    },
  })

  const startMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post<TunnelStartResponse>('/phish/tunnel/start', {
        tool: 'ssh',
        port: parseInt(port || '0') || 80,
        remote: remote.trim() || null,
        remote_port: parseInt(remotePort || '0') || 80,
      })
      return res.data
    },
    onSettled: () => refetchStatus(),
  })

  const stopMutation = useMutation({
    mutationFn: async (t: string) => {
      const res = await api.post<TunnelStopResponse>('/phish/tunnel/stop', { tool: t })
      return res.data
    },
    onSettled: () => refetchStatus(),
  })

  const manualMutation = useMutation({
    mutationFn: async (url: string) => {
      const res = await api.post<TunnelManualResponse>('/phish/tunnel/manual', { url })
      return res.data
    },
    onSuccess: (data) => {
      setManualMsg({ ok: data.success, text: data.message || data.error || '' })
      refetchStatus()
    },
  })

  const templates: PhishTemplate[] = kind === 'sms' ? templatesData?.sms || [] : templatesData?.email || []
  const activeTpl = templates.find((t) => t.id === templateId)

  const defaultLink = manualUrl || ssh.url || ''

  const selectTemplate = (t: PhishTemplate) => {
    setTemplateId(t.id)
    setRendered(null)
    const initial: Record<string, string> = {}
    for (const v of t.variables) {
      if (v === 'platform') initial[v] = 'GitHub'
      if (v === 'company') initial[v] = 'Acme Corp'
      if (v === 'link') initial[v] = defaultLink || 'https://your-tunnel-url.example/reset'
      if (v === 'expiry') initial[v] = '24 hours'
      if (v === 'first_name') initial[v] = 'Alex'
      if (v === 'last_name') initial[v] = 'Johnson'
      if (v === 'email') initial[v] = 'alex@example.com'
      if (v === 'code') initial[v] = '482910'
      if (v === 'amount') initial[v] = '$149.00'
      if (v === 'sender') initial[v] = 'IT Helpdesk'
      if (v === 'reference') initial[v] = 'INV-2026-0417'
      if (v === 'last4') initial[v] = '4821'
      if (v === 'merchant') initial[v] = 'Amazon.com'
      if (v === 'bank') initial[v] = 'First National Bank'
      if (v === 'telecom') initial[v] = 'Verizon'
      if (v === 'tracking') initial[v] = '1Z999AA10123456784'
      if (v === 'order') initial[v] = '112-3456789-0'
      if (v === 'document') initial[v] = 'Employment_Agreement_2026.pdf'
      if (v === 'filename') initial[v] = 'quarterly-report.xlsx'
      if (v === 'location') initial[v] = 'Berlin, Germany'
      if (v === 'device') initial[v] = 'Chrome on Windows 11'
      if (v === 'count') initial[v] = '12'
      if (v === 'date') initial[v] = 'Monday, August 10'
      if (v === 'time') initial[v] = '10:30 AM'
      if (v === 'health') initial[v] = 'CityCare Health'
    }
    setVars(initial)
  }

  const renderTemplate = () => {
    if (!templateId) return
    const res = api.post<RenderedTemplate>('/phish/template/render', { kind, template_id: templateId, variables: vars })
    res.then(({ data }) => setRendered(data))
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader
        title="Social Phish"
        subtitle="Phishing campaign toolkit: expose a local server with tunnels and generate SMS / email lures"
        icon={<Globe className="w-8 h-8" />}
        color="cyan"
      >
        <div className="flex items-start gap-2 px-1">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <p className="text-xs text-gray-500">Authorized engagements only. Never use against targets without explicit written permission.</p>
        </div>
      </PageHeader>

      {/* Tunnels */}
      <div className="space-y-3">
        <SectionHeader icon={<Rocket className="w-4 h-4 text-cyan-400" />} title="Exposure" />

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
          {/* SSH reverse tunnel */}
          <Card className="flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span className="text-sm font-medium text-gray-200">{toolLabels.ssh}</span>
              </div>
              <span
                className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                  ssh.running ? 'bg-green-400/10 text-green-400' : 'bg-amber-400/10 text-amber-400'
                }`}
              >
                {ssh.running ? 'LIVE' : 'Idle'}
              </span>
            </div>
            <p className="text-[11px] text-gray-600 leading-relaxed">{ssh.help}</p>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-[10px] text-gray-500 uppercase tracking-wider block mb-1">Local port</label>
                <input
                  type="number"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  className="w-full bg-gray-800/80 border border-gray-700/60 rounded-lg px-3 py-2.5 text-sm text-white focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors min-h-[44px]"
                />
              </div>
              <div>
                <label className="text-[10px] text-gray-500 uppercase tracking-wider block mb-1">Remote port</label>
                <input
                  type="number"
                  value={remotePort}
                  onChange={(e) => setRemotePort(e.target.value)}
                  className="w-full bg-gray-800/80 border border-gray-700/60 rounded-lg px-3 py-2.5 text-sm text-white focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors min-h-[44px]"
                />
              </div>
            </div>
            <div>
              <label className="text-[10px] text-gray-500 uppercase tracking-wider block mb-1">Remote target (user@host)</label>
              <input
                type="text"
                value={remote}
                onChange={(e) => setRemote(e.target.value)}
                placeholder="user@vps.example.com"
                className="w-full bg-gray-800/80 border border-gray-700/60 rounded-lg px-3 py-2.5 text-sm text-white focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors min-h-[44px]"
              />
            </div>
            {ssh.running && (
              <div className="flex items-center justify-between gap-2 bg-gray-950 rounded-lg border border-gray-800 px-2 py-1.5 min-w-0">
                <span className="text-[11px] text-gray-500 shrink-0">Tunnel up, port {ssh.port}</span>
                {ssh.url && (
                  <a href={ssh.url} target="_blank" rel="noopener noreferrer" className="text-[11px] text-cyan-400 font-mono truncate hover:underline">
                    {ssh.url}
                  </a>
                )}
              </div>
            )}
            {ssh.running ? (
              <Button color="red" onClick={() => stopMutation.mutate('ssh')} loading={stopMutation.isPending}>
                <Square className="w-4 h-4 mr-2" /> Stop tunnel
              </Button>
            ) : (
              <Button color="cyan" onClick={() => startMutation.mutate()} loading={startMutation.isPending} disabled={!remote.trim()}>
                <Play className="w-4 h-4 mr-2" /> Start reverse tunnel
              </Button>
            )}
            {startMutation.data && (
              <div className={`text-xs ${startMutation.data.success ? 'text-green-400' : 'text-red-400'}`}>
                {startMutation.data.message || startMutation.data.error}
              </div>
            )}
            {stopMutation.data && (
              <div className={`text-xs ${stopMutation.data.success ? 'text-green-400' : 'text-red-400'}`}>
                {stopMutation.data.message || stopMutation.data.error}
              </div>
            )}
          </Card>

          {/* Public URL */}
          <Card className="flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Link2 className="w-4 h-4 text-cyan-400" />
                <span className="text-sm font-medium text-gray-200">Public URL</span>
              </div>
              {defaultLink && (
                <span className="text-[10px] px-1.5 py-0.5 rounded font-medium bg-green-400/10 text-green-400">IN USE</span>
              )}
            </div>
            <p className="text-[11px] text-gray-600 leading-relaxed">
              Paste the public URL of your phishing server here. It becomes the default {'{link}'} variable for every SMS and email template.
            </p>
            <div className="flex gap-2">
              <input
                type="text"
                value={publicUrlInput || defaultLink}
                onChange={(e) => { setPublicUrlInput(e.target.value); setManualMsg(null) }}
                placeholder="https://your-server.example/reset"
                className="flex-1 min-w-0 bg-gray-800/80 border border-gray-700/60 rounded-lg px-3 py-2.5 text-sm text-white placeholder-gray-500 focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors min-h-[44px] font-mono"
              />
              <Button color="cyan" onClick={() => manualMutation.mutate(publicUrlInput || defaultLink)} loading={manualMutation.isPending}>
                <Save className="w-4 h-4 mr-2" /> Save
              </Button>
              {defaultLink && (
                <button
                  onClick={() => manualMutation.mutate('')}
                  title="Clear public URL"
                  className="min-w-[44px] min-h-[44px] px-3 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 hover:text-red-400 hover:border-red-800 transition-colors flex items-center justify-center"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              )}
            </div>
            {manualMsg && (
              <div className={`text-xs ${manualMsg.ok ? 'text-green-400' : 'text-red-400'}`}>{manualMsg.text}</div>
            )}
            {defaultLink && (
              <div className="flex items-center gap-1.5 bg-gray-950 rounded-lg border border-gray-800 px-2 py-1.5 min-w-0">
                <Link2 className="w-3 h-3 text-cyan-400 shrink-0" />
                <a href={defaultLink} target="_blank" rel="noopener noreferrer" className="text-[11px] text-cyan-400 font-mono truncate hover:underline">
                  {defaultLink}
                </a>
                <button
                  onClick={() => copy(defaultLink, 'publicurl')}
                  className="ml-auto p-1.5 rounded text-gray-500 hover:text-white hover:bg-gray-800 transition-colors min-w-[32px] min-h-[32px] flex items-center justify-center"
                  title="Copy public URL"
                >
                  {copied === 'publicurl' ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            )}
            <div className="text-[11px] text-gray-600">
              Tip: run your phishing server locally (e.g. on port {port}), then use an SSH reverse tunnel{' '}
              <span className="text-gray-400 font-mono">ssh -R {remotePort || 80}:localhost:{port} {remote || 'user@host'}</span>{' '}
              or your own hosting/domain to expose it publicly.
            </div>
          </Card>
        </div>
      </div>

      {/* Template generator */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <MessageSquare className="w-4 h-4 text-cyan-400" />
          <div className="text-[11px] font-bold uppercase tracking-widest text-gray-500">Template Generator</div>
        </div>

        <Card>
          <div className="flex flex-wrap gap-2 mb-4">
            <button
              onClick={() => { setKind('sms'); setTemplateId(''); setRendered(null) }}
              className={`flex items-center gap-1.5 text-sm px-4 py-2.5 rounded-lg border transition-colors min-h-[44px] ${
                kind === 'sms' ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-400' : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'
              }`}
            >
              <MessageSquare className="w-4 h-4" /> SMS
            </button>
            <button
              onClick={() => { setKind('email'); setTemplateId(''); setRendered(null) }}
              className={`flex items-center gap-1.5 text-sm px-4 py-2.5 rounded-lg border transition-colors min-h-[44px] ${
                kind === 'email' ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-400' : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'
              }`}
            >
              <Mail className="w-4 h-4" /> Email Letter
            </button>
          </div>

          <div className="flex flex-wrap gap-2 mb-4">
            {templates.map((t) => (
              <button
                key={t.id}
                onClick={() => selectTemplate(t)}
                className={`text-xs px-3 py-2 rounded-lg border transition-colors min-h-[36px] flex items-center gap-2 ${
                  templateId === t.id ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-400' : 'bg-gray-800/60 border-gray-700/60 text-gray-300 hover:text-white'
                }`}
                title={t.subject || t.body}
              >
                <span
                  className="w-2 h-2 rounded-full shrink-0"
                  style={{ backgroundColor: t.brand_color || '#555' }}
                />
                {t.brand && <span className="text-[10px] uppercase tracking-wider opacity-60">{t.brand}</span>}
                {t.name}
              </button>
            ))}
          </div>

          {activeTpl && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="space-y-2.5">
                <div className="text-[10px] text-gray-500 uppercase tracking-wider">Variables</div>
                {activeTpl.variables.map((v) => (
                  <div key={v}>
                    <label className="text-xs text-gray-400 mb-1 block">{VARIABLE_LABELS[v] || v}</label>
                    <input
                      type="text"
                      value={vars[v] || ''}
                      onChange={(e) => setVars((prev) => ({ ...prev, [v]: e.target.value }))}
                      className="w-full bg-gray-800/80 border border-gray-700/60 rounded-lg px-3 py-2.5 text-sm text-white placeholder-gray-500 focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 outline-none transition-colors min-h-[44px]"
                    />
                  </div>
                ))}
                <Button color="cyan" onClick={renderTemplate} className="w-full">
                  <Play className="w-4 h-4 mr-2" /> Render {kind === 'sms' ? 'SMS' : 'Letter'}
                </Button>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="text-[10px] text-gray-500 uppercase tracking-wider">Preview</div>
                  {kind === 'email' && (
                    <div className="flex gap-1">
                      <button
                        onClick={() => setPreviewMode('html')}
                        className={`text-[10px] px-2 py-1 rounded ${previewMode === 'html' ? 'bg-cyan-500/15 text-cyan-400' : 'text-gray-500 hover:text-gray-300'}`}
                      >
                        HTML
                      </button>
                      <button
                        onClick={() => setPreviewMode('plain')}
                        className={`text-[10px] px-2 py-1 rounded ${previewMode === 'plain' ? 'bg-cyan-500/15 text-cyan-400' : 'text-gray-500 hover:text-gray-300'}`}
                      >
                        Plain
                      </button>
                    </div>
                  )}
                </div>
                {rendered ? (
                  <div className="bg-gray-950 border border-gray-800 rounded-lg p-4 space-y-3">
                    {rendered.error && <div className="text-xs text-red-400">{rendered.error}</div>}
                    {rendered.success && (
                      <>
                        {rendered.subject && (
                          <div className="flex items-start justify-between gap-2">
                            <div className="min-w-0">
                              <div className="text-[10px] text-gray-600 uppercase tracking-wider">Subject</div>
                              <div className="text-sm text-gray-200 font-medium">{rendered.subject}</div>
                            </div>
                            <button
                              onClick={() => copy(rendered.subject || '', 'subject')}
                              className="p-2 rounded-lg text-gray-500 hover:text-white hover:bg-gray-800 transition-colors min-w-[36px] min-h-[36px] flex items-center justify-center"
                              title="Copy subject"
                            >
                              {copied === 'subject' ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                            </button>
                          </div>
                        )}
                        {rendered.brand && (
                          <div className="flex items-center gap-1.5 text-[10px] text-gray-500">
                            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: rendered.brand_color || '#555' }} />
                            Branded as {rendered.brand}
                          </div>
                        )}
                        {kind === 'email' && rendered.body_html && previewMode === 'html' ? (
                          <iframe
                            title="Email preview"
                            sandbox=""
                            srcDoc={rendered.body_html}
                            className="w-full h-80 bg-white rounded border border-gray-800"
                          />
                        ) : (
                          <div className="flex items-start justify-between gap-2">
                            <pre className="text-xs text-gray-300 whitespace-pre-wrap font-sans leading-relaxed flex-1 break-all">{rendered.body}</pre>
                            <button
                              onClick={() => copy(rendered.body || '', 'body')}
                              className="p-2 rounded-lg text-gray-500 hover:text-white hover:bg-gray-800 transition-colors min-w-[36px] min-h-[36px] flex items-center justify-center"
                              title="Copy body"
                            >
                              {copied === 'body' ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                            </button>
                          </div>
                        )}
                        {rendered.missing && rendered.missing.length > 0 && (
                          <div className="text-[11px] text-amber-400">
                            Missing variables: {rendered.missing.join(', ')}
                          </div>
                        )}
                      </>
                    )}
                  </div>
                ) : (
                  <div className="bg-gray-950/60 border border-gray-800 rounded-lg p-4 text-xs text-gray-600">
                    Fill the variables and click Render to preview the message.
                  </div>
                )}
              </div>
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}
