import { lazy, Suspense, useState, useEffect, useCallback } from 'react'
import { Routes, Route } from 'react-router-dom'
import { Sidebar, SidebarCtx } from '../components/Layout'
import FloatingAi from '../components/FloatingAi'
import Login from '../pages/Login'
import api from '../api'

const Dashboard = lazy(() => import('../pages/Dashboard'))
const Modules = lazy(() => import('../pages/Modules'))
const ModuleDetail = lazy(() => import('../pages/ModuleDetail'))
const Targets = lazy(() => import('../pages/Targets'))
const Sessions = lazy(() => import('../pages/Sessions'))
const CveFeed = lazy(() => import('../pages/CveFeed'))
const Workspace = lazy(() => import('../pages/Workspace'))
const Top10 = lazy(() => import('../pages/Top10'))
const AutoScan = lazy(() => import('../pages/AutoScan'))
const BruteForce = lazy(() => import('../pages/BruteForce'))
const PasswordSpray = lazy(() => import('../pages/PasswordSpray'))
const AccountEnum = lazy(() => import('../pages/AccountEnum'))
const CredStuffing = lazy(() => import('../pages/CredStuffing'))
const SocialPhish = lazy(() => import('../pages/SocialPhish'))
const CmsExploit = lazy(() => import('../pages/CmsExploit'))
const FormCrawler = lazy(() => import('../pages/FormCrawler'))
const AutoBrute = lazy(() => import('../pages/AutoBrute'))
const SecretScan = lazy(() => import('../pages/SecretScan'))
const Fuzzer = lazy(() => import('../pages/Fuzzer'))
const SploitusScanner = lazy(() => import('../pages/SploitusScanner'))
const SploitusExploit = lazy(() => import('../pages/SploitusExploit'))
const AiHelper = lazy(() => import('../pages/AiHelper'))
const Dorking = lazy(() => import('../pages/Dorking'))
const OsintIdentity = lazy(() => import('../pages/OsintIdentity'))
const FaceSearch = lazy(() => import('../pages/FaceSearch'))
const PortScanner = lazy(() => import('../pages/PortScanner'))
const CredVault = lazy(() => import('../pages/CredVault'))
const Payloads = lazy(() => import('../pages/Payloads'))
const Jobs = lazy(() => import('../pages/Jobs'))
const Bugbounty = lazy(() => import('../pages/Bugbounty'))

function LoadingFallback() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="flex items-center gap-3 text-webforge-400 text-sm">
        <div className="w-5 h-5 border-2 border-webforge-400 border-t-transparent rounded-full animate-spin" />
        <span>Loading...</span>
      </div>
    </div>
  )
}

function NotFound() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <div className="text-4xl text-gray-600 mb-2">404</div>
        <p className="text-sm text-gray-500">Page not found</p>
      </div>
    </div>
  )
}

type AuthStatus = 'loading' | 'authed' | 'guest'

export default function App() {
  const [auth, setAuth] = useState<AuthStatus>('loading')

  const checkAuth = useCallback(async () => {
    try {
      const res = await api.get('/auth/status')
      setAuth(res.data.authenticated ? 'authed' : 'guest')
    } catch {
      setAuth('guest')
    }
  }, [])

  useEffect(() => {
    checkAuth()
    const onExpired = () => setAuth('guest')
    window.addEventListener('auth:expired', onExpired)
    const interval = setInterval(checkAuth, 60000)
    return () => {
      window.removeEventListener('auth:expired', onExpired)
      clearInterval(interval)
    }
  }, [checkAuth])

  if (auth === 'loading') {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-950">
        <div className="flex items-center gap-3 text-webforge-400 text-sm">
          <div className="w-6 h-6 border-2 border-webforge-400 border-t-transparent rounded-full animate-spin" />
          <span>Loading WebForge...</span>
        </div>
      </div>
    )
  }

  if (auth === 'guest') {
    return <Login onSuccess={() => setAuth('authed')} />
  }

  return <MainApp />
}

function MainApp() {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <SidebarCtx.Provider value={{ open: sidebarOpen, setOpen: setSidebarOpen, toggle: () => setSidebarOpen((p) => !p) }}>
      <div className="flex h-screen bg-gray-950 text-gray-100 overflow-hidden">
        <Sidebar />
        <main className="flex-1 min-w-0 overflow-y-auto">
          <div className="p-4 sm:p-6">
            <Suspense fallback={<LoadingFallback />}>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/modules" element={<Modules />} />
                <Route path="/modules/:modulePath/*" element={<ModuleDetail />} />
                <Route path="/scan" element={<AutoScan />} />
                <Route path="/crawl" element={<FormCrawler />} />
                <Route path="/auto-brute" element={<AutoBrute />} />
                <Route path="/bruteforce" element={<BruteForce />} />
                <Route path="/spray" element={<PasswordSpray />} />
                <Route path="/enum" element={<AccountEnum />} />
                <Route path="/creds" element={<CredStuffing />} />
                <Route path="/social" element={<SocialPhish />} />
                <Route path="/cms" element={<CmsExploit />} />
                <Route path="/targets" element={<Targets />} />
                <Route path="/sessions" element={<Sessions />} />
                <Route path="/cve" element={<CveFeed />} />
                <Route path="/top10" element={<Top10 />} />
                <Route path="/workspace" element={<Workspace />} />
                <Route path="/secrets" element={<SecretScan />} />
                <Route path="/fuzz" element={<Fuzzer />} />
                <Route path="/sploitus" element={<SploitusScanner />} />
                <Route path="/sploitus-exploit" element={<SploitusExploit />} />
                <Route path="/ai" element={<AiHelper />} />
                <Route path="/dorking" element={<Dorking />} />
                <Route path="/osint" element={<OsintIdentity />} />
                <Route path="/face-search" element={<FaceSearch />} />
                <Route path="/portscan" element={<PortScanner />} />
                <Route path="/credvault" element={<CredVault />} />
                <Route path="/payloads" element={<Payloads />} />
                <Route path="/jobs" element={<Jobs />} />
                <Route path="/bugbounty" element={<Bugbounty />} />
                <Route path="*" element={<NotFound />} />
              </Routes>
            </Suspense>
          </div>
        </main>
      </div>
      <FloatingAi />
    </SidebarCtx.Provider>
  )
}
