import { useEffect, useState, type ReactNode } from 'react'

import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { Icon } from '@/shared/components/icon'

export type Page = 'overview' | 'applications'

interface AppShellProps {
  page: Page
  applicationCount: number
  canSync: boolean
  syncing: boolean
  onNavigate: (page: Page) => void
  onSync: () => void
  children: ReactNode
}

export function AppShell({
  page,
  applicationCount,
  canSync,
  syncing,
  onNavigate,
  onSync,
  children,
}: AppShellProps) {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains('dark'))

  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = (event: MediaQueryListEvent) => {
      try {
        if (localStorage.getItem('fleetctrl-theme')) return
      } catch {}
      document.documentElement.classList.toggle('dark', event.matches)
      setDark(event.matches)
    }
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])

  const toggleTheme = () => {
    const next = !dark
    setDark(next)
    document.documentElement.classList.toggle('dark', next)
    try {
      localStorage.setItem('fleetctrl-theme', next ? 'dark' : 'light')
    } catch {}
  }

  const navigationClass = (active: boolean) => cn(
    'h-8 w-full justify-start gap-2 rounded-sm border-0 px-2.5 text-xs text-sidebar-foreground',
    'hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
    '[&_.icon]:size-3.5',
    active && 'bg-sidebar-accent font-medium text-sidebar-accent-foreground',
  )

  return (
    <div className="grid h-screen min-h-[36rem] grid-cols-[13rem_minmax(0,1fr)] overflow-hidden max-[760px]:block max-[760px]:h-auto max-[760px]:min-h-screen">
      <aside className="flex h-screen flex-col border-r border-sidebar-border bg-sidebar p-2 max-[760px]:h-auto max-[760px]:w-full max-[760px]:flex-row max-[760px]:items-center max-[760px]:border-r-0 max-[760px]:border-b max-[760px]:px-2 max-[760px]:py-1.5">
        <div className="flex h-10 items-center px-2.5 max-[760px]:mr-4 max-[760px]:h-auto max-[760px]:px-0">
          <strong className="text-sm">FleetCtrl</strong>
        </div>
        <p className="mb-1 px-2.5 text-[0.65rem] uppercase tracking-wider text-muted-foreground max-[760px]:hidden">
          Device
        </p>
        <nav className="grid gap-0.5 max-[760px]:ml-auto max-[760px]:flex">
          <Button
            variant="ghost"
            className={navigationClass(page === 'overview')}
            onClick={() => onNavigate('overview')}
          >
            <Icon name="grid" />
            Overview
          </Button>
          <Button
            variant="ghost"
            className={navigationClass(page === 'applications')}
            onClick={() => onNavigate('applications')}
          >
            <Icon name="apps" />
            Applications
            <span className="ml-auto text-muted-foreground max-[760px]:hidden">
              {applicationCount}
            </span>
          </Button>
        </nav>
        <div className="mt-auto flex min-w-0 items-center gap-2.5 border-t border-sidebar-border px-2 pt-2 pb-0.5 max-[760px]:hidden">
          <span className="grid size-6 shrink-0 place-items-center rounded-sm border border-border bg-card text-muted-foreground [&_.icon]:size-3">
            <Icon name="server" />
          </span>
          <div className="min-w-0">
            <strong className="block truncate text-xs">This device</strong>
            <span className="block truncate text-[0.65rem] text-muted-foreground">
              Managed by your organization
            </span>
          </div>
        </div>
      </aside>

      <main className="grid h-screen min-h-0 min-w-0 grid-rows-[auto_minmax(0,1fr)] max-[760px]:h-auto max-[760px]:min-h-[calc(100vh-3rem)] max-[760px]:grid-rows-[auto_minmax(0,1fr)]">
        <header className="flex h-12 items-center justify-between gap-4 border-b border-border bg-background px-5 max-[760px]:px-3">
          <h1 className="m-0 text-sm font-medium">
            {page === 'overview' ? 'Device status' : 'Application management'}
          </h1>
          <div className="flex items-center gap-1.5">
            <Button
              variant="ghost"
              size="icon"
              className="size-8 rounded-sm text-muted-foreground hover:text-foreground"
              aria-label={dark ? 'Switch to light mode' : 'Switch to dark mode'}
              onClick={toggleTheme}
            >
              <Icon name={dark ? 'sun' : 'moon'} className="size-3.5" />
            </Button>
            <Button
              size="sm"
              disabled={syncing || !canSync}
              onClick={onSync}
            >
              <Icon name="sync" className={cn('size-3.5', syncing && 'animate-spin')} />
              {syncing ? 'Syncing…' : 'Sync now'}
            </Button>
          </div>
        </header>
        <div className="min-h-0 overflow-y-auto [scrollbar-color:color-mix(in_oklch,var(--muted-foreground)_45%,transparent)_transparent] [scrollbar-width:thin] max-[760px]:overflow-visible">
          {children}
        </div>
      </main>
    </div>
  )
}
