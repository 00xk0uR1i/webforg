export type JobStatus = 'queued' | 'running' | 'done' | 'error' | 'cancelled' | 'cancelling'

export interface Job {
  id: string
  name: string
  status: JobStatus
  progress: number
  message: string
  created_at: number
  updated_at: number
  result?: unknown
  error?: string
}

export interface JobFull extends Job {
  result: Record<string, unknown>
}

export interface JobListResponse {
  jobs: Job[]
}

export interface JobSubmitResponse {
  job_id: string
  action: string
}
