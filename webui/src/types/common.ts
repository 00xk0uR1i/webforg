export interface OkResponse {
  ok: boolean
}

export interface SuccessResponse {
  success: boolean
}

export interface ValidationErrorItem {
  loc: (string | number)[]
  msg: string
  type?: string
}

export interface ApiErrorBody {
  detail?: string | ValidationErrorItem[]
}

export interface ApiError {
  message?: string
  userMessage?: string
  response?: {
    status?: number
    data?: ApiErrorBody
  }
}
