import { useState } from 'react'
import { Skull, Lock, ShieldCheck, AlertTriangle, Eye, EyeOff } from 'lucide-react'
import { Button, Input } from '../components/UI'
import api from '../api'
import { getErrorMessage } from '../utils/error'
import type { LoginResponse } from '../types'

interface LoginProps {
  onSuccess: () => void
}

export default function Login({ onSuccess }: LoginProps) {
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!password) return
    setLoading(true)
    setError('')
    try {
      await api.post<LoginResponse>('/auth/login', { password })
      onSuccess()
    } catch (err) {
      setError(getErrorMessage(err) || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
      <div className="w-full max-w-sm animate-fade-in">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-webforge-500/10 border border-webforge-500/20 mb-4">
            <Skull className="w-8 h-8 text-red-500" />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">WebForge</h1>
          <p className="text-sm text-gray-500 mt-1">Web Exploitation Framework</p>
        </div>

        {/* Form */}
        <form onSubmit={handleLogin} className="bg-gray-900/60 border border-gray-800/40 rounded-2xl p-6 space-y-5 animate-slide-up">
          <div className="flex items-center gap-2 text-xs text-gray-400">
            <ShieldCheck className="w-4 h-4 text-green-400/80" />
            <span>Authentication required</span>
          </div>

          <div className="relative">
            <Input
              label="Admin Password"
              type={showPw ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              autoFocus
              autoComplete="current-password"
            />
            <button
              type="button"
              onClick={() => setShowPw((p) => !p)}
              className="absolute right-3 bottom-3 text-gray-500 hover:text-gray-300 p-1 transition-colors"
              aria-label={showPw ? 'Hide password' : 'Show password'}
            >
              {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>

          {error && (
            <div className="flex items-center gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}

          <Button type="submit" disabled={!password || loading} loading={loading} color="webforge" className="w-full">
            <Lock className="w-4 h-4" /> Unlock
          </Button>
        </form>

        <p className="text-center text-[10px] text-gray-600 mt-4">
          Set the WEBFORGE_PASSWORD environment variable to configure the admin password.
        </p>
      </div>
    </div>
  )
}
