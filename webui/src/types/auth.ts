export interface LoginResponse {
  success: boolean
  authenticated: boolean
  message?: string
}

export interface AuthStatus {
  authenticated: boolean
  auth_enabled: boolean
}
