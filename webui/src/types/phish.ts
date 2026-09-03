export interface TunnelInfo {
  tool: string
  installed: boolean
  running: boolean
  url: string | null
  port: number | null
  pid: number | null
  started_at: string | null
  help: string
}

export interface TunnelStatusData {
  tunnels: Record<string, TunnelInfo>
  manual_url: string
}

export interface TunnelStartResponse {
  success: boolean
  tool: string
  url?: string | null
  port?: number | null
  message?: string
  error?: string
}

export interface TunnelStopResponse {
  success: boolean
  tool: string
  message?: string
  error?: string
}

export interface TunnelManualResponse {
  success: boolean
  url: string
  message?: string
  error?: string
}

export interface PhishTemplate {
  id: string
  name: string
  brand?: string
  brand_color?: string
  subject?: string
  body: string
  variables: string[]
}

export interface PhishTemplatesResponse {
  sms: PhishTemplate[]
  email: PhishTemplate[]
}

export interface RenderedTemplate {
  success: boolean
  kind?: string
  id?: string
  name?: string
  brand?: string
  brand_color?: string
  subject?: string
  body?: string
  body_html?: string
  missing?: string[]
  error?: string
}
