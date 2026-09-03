export interface Shell {
  name: string
  language: string
  os: string
  cmd: string
  raw: string
  description: string
}

export interface ShellsResponse {
  shells: Shell[]
  encoder: string
  listener: string
  msf_listener: string
}

export interface Encoder {
  name: string
  description: string
}

export interface EncodersResponse {
  encoders: Encoder[]
}

export interface PayloadSummary {
  name: string
  description: string
  language: string
}

export interface PayloadListResponse {
  payloads: PayloadSummary[]
}

export interface PayloadGenerateResponse {
  payload: string
  one_liner: string
  encoder: string
  raw: string
  note?: string
}

export interface FingerprintResponse {
  fingerprint: Record<string, unknown>
}
