export interface CrawlerForm {
  action_url: string
  method: string
  user_field: string
  pass_field: string
  hidden_fields: Record<string, string>
  csrf_field: string
  csrf_token: string
  enctype: string
}

export interface CrawlerResult {
  success: boolean
  forms: CrawlerForm[]
  pages_crawled: number
  elapsed?: number
  error?: string
}
