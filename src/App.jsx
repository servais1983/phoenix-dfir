import { useState } from 'react'
import { AppProvider, useApp } from '@/context/AppContext'
import { Toaster } from '@/components/ui/sonner.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { Separator } from '@/components/ui/separator.jsx'
import { ScrollArea } from '@/components/ui/scroll-area.jsx'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip.jsx'
import {
  LayoutDashboard,
  FolderSearch,
  Search,
  Clock,
  AlertTriangle,
  FileText,
  Settings,
  Shield,
  Hash,
  ChevronLeft,
  ChevronRight,
  Wifi,
  WifiOff,
} from 'lucide-react'
import './App.css'

import DashboardPage from '@/pages/DashboardPage'
import InvestigationsPage from '@/pages/InvestigationsPage'
import AnalyzerPage from '@/pages/AnalyzerPage'
import TimelinePage from '@/pages/TimelinePage'
import IocsPage from '@/pages/IocsPage'
import ReportsPage from '@/pages/ReportsPage'
import SettingsPage from '@/pages/SettingsPage'
import HashToolPage from '@/pages/HashToolPage'

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'investigations', label: 'Enquetes', icon: FolderSearch },
  { id: 'analyzer', label: 'Analyseur', icon: Search },
  { id: 'timeline', label: 'Timeline', icon: Clock },
  { id: 'iocs', label: 'IoCs', icon: AlertTriangle },
  { id: 'reports', label: 'Rapports', icon: FileText },
  { id: 'hash', label: 'Hash Tool', icon: Hash },
  { id: 'settings', label: 'Parametres', icon: Settings },
]

function PageRenderer({ activePage }) {
  switch (activePage) {
    case 'dashboard': return <DashboardPage />
    case 'investigations': return <InvestigationsPage />
    case 'analyzer': return <AnalyzerPage />
    case 'timeline': return <TimelinePage />
    case 'iocs': return <IocsPage />
    case 'reports': return <ReportsPage />
    case 'settings': return <SettingsPage />
    case 'hash': return <HashToolPage />
    default: return <DashboardPage />
  }
}

function AppLayout() {
  const [activePage, setActivePage] = useState('dashboard')
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const { backendStatus, currentInvestigation, investigations } = useApp()

  return (
    <div className="flex h-screen bg-gray-950 text-gray-100 overflow-hidden">
      {/* Sidebar */}
      <aside className={`flex flex-col border-r border-gray-800/60 bg-gray-900/40 backdrop-blur-sm transition-all duration-200 ${sidebarCollapsed ? 'w-16' : 'w-56'}`}>
        {/* Logo */}
        <div className="flex items-center h-14 px-3 border-b border-gray-800/60">
          <div className="flex items-center gap-2 min-w-0">
            <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-orange-600/20 shrink-0">
              <Shield className="h-4 w-4 text-orange-500" />
            </div>
            {!sidebarCollapsed && (
              <div className="min-w-0">
                <h1 className="text-sm font-semibold text-white truncate tracking-tight">Phoenix DFIR</h1>
                <p className="text-[10px] text-gray-500 truncate">v2.0 - Forensics Platform</p>
              </div>
            )}
          </div>
        </div>

        {/* Navigation */}
        <ScrollArea className="flex-1 py-2">
          <nav className="flex flex-col gap-0.5 px-2">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon
              const isActive = activePage === item.id
              const isSeparator = item.id === 'hash'

              return (
                <div key={item.id}>
                  {isSeparator && <Separator className="my-2 bg-gray-800/60" />}
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <button
                        onClick={() => setActivePage(item.id)}
                        className={`flex items-center gap-3 w-full rounded-md px-2.5 py-2 text-sm transition-colors ${
                          isActive
                            ? 'bg-orange-600/15 text-orange-400'
                            : 'text-gray-400 hover:bg-gray-800/50 hover:text-gray-200'
                        }`}
                      >
                        <Icon className={`h-4 w-4 shrink-0 ${isActive ? 'text-orange-500' : ''}`} />
                        {!sidebarCollapsed && (
                          <span className="truncate">{item.label}</span>
                        )}
                      </button>
                    </TooltipTrigger>
                    {sidebarCollapsed && (
                      <TooltipContent side="right">
                        {item.label}
                      </TooltipContent>
                    )}
                  </Tooltip>
                </div>
              )
            })}
          </nav>
        </ScrollArea>

        {/* Sidebar Footer */}
        <div className="border-t border-gray-800/60 p-2">
          {!sidebarCollapsed && currentInvestigation && (
            <div className="mb-2 px-2 py-1.5 rounded-md bg-gray-800/50">
              <p className="text-[10px] text-gray-500 uppercase tracking-wider">Enquete active</p>
              <p className="text-xs text-gray-300 truncate">{currentInvestigation.name || currentInvestigation.nom_du_cas}</p>
            </div>
          )}
          <button
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            className="flex items-center justify-center w-full rounded-md p-1.5 text-gray-500 hover:bg-gray-800/50 hover:text-gray-300 transition-colors"
          >
            {sidebarCollapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Bar */}
        <header className="flex items-center justify-between h-14 px-4 border-b border-gray-800/60 bg-gray-900/20 backdrop-blur-sm shrink-0">
          <div className="flex items-center gap-3">
            <h2 className="text-base font-medium text-white">
              {NAV_ITEMS.find(n => n.id === activePage)?.label || 'Dashboard'}
            </h2>
            {currentInvestigation && (
              <Badge variant="outline" className="text-xs text-gray-400 border-gray-700 font-normal">
                {currentInvestigation.name || currentInvestigation.nom_du_cas}
              </Badge>
            )}
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              {backendStatus === 'online' ? (
                <Wifi className="h-3.5 w-3.5 text-emerald-500" />
              ) : (
                <WifiOff className="h-3.5 w-3.5 text-red-400" />
              )}
              <span className={`text-xs ${backendStatus === 'online' ? 'text-emerald-400' : 'text-red-400'}`}>
                {backendStatus === 'online' ? 'Backend connecte' : 'Backend deconnecte'}
              </span>
            </div>
            <Separator orientation="vertical" className="h-4 bg-gray-800" />
            <Badge variant="outline" className="text-xs border-gray-700 text-gray-400 font-normal">
              {investigations.length} enquete{investigations.length !== 1 ? 's' : ''}
            </Badge>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-auto">
          <div className="p-6">
            <PageRenderer activePage={activePage} />
          </div>
        </main>
      </div>

      <Toaster position="bottom-right" theme="dark" />
    </div>
  )
}

function App() {
  return (
    <AppProvider>
      <AppLayout />
    </AppProvider>
  )
}

export default App
