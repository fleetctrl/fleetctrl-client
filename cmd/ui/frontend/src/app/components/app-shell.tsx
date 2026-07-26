import type { ReactNode } from 'react'

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
  const navigationClass = (active: boolean) => cn(
    'relative h-[2.45rem] w-full justify-start gap-[0.7rem] rounded-[0.45rem] border-0 px-[0.72rem] text-[0.78rem] font-normal text-sidebar-foreground',
    'transition-[background-color,color,transform] duration-150 hover:bg-sidebar-accent/70 hover:text-sidebar-accent-foreground active:scale-[0.985]',
    '[&_.icon]:size-[0.95rem]',
    active && [
      'bg-sidebar-accent text-sidebar-accent-foreground shadow-sm',
      "before:absolute before:-left-[0.05rem] before:h-4 before:w-[0.2rem] before:rounded-full before:bg-primary before:content-['']",
    ],
  )

  return (
    <div className="grid h-screen min-h-[36rem] grid-cols-[14.5rem_minmax(0,1fr)] overflow-hidden bg-transparent max-[760px]:block max-[760px]:h-auto max-[760px]:min-h-screen">
      <aside className="relative flex h-screen flex-col border-r border-sidebar-border bg-sidebar/85 p-3 backdrop-blur-2xl max-[760px]:h-auto max-[760px]:w-full max-[760px]:flex-row max-[760px]:items-center max-[760px]:border-r-0 max-[760px]:border-b max-[760px]:px-2.5 max-[760px]:py-2">
        <div className="mb-[1.15rem] flex min-h-12 items-center px-2.5 max-[760px]:mr-4 max-[760px]:mb-0 max-[760px]:min-h-10 max-[760px]:px-0">
          <strong className="font-display text-base font-semibold tracking-[-0.025em]">FleetCtrl</strong>
        </div>
        <p className="mb-1.5 px-[0.7rem] text-[0.66rem] font-medium text-muted-foreground max-[760px]:hidden">Device</p>
        <nav className="grid gap-1 max-[760px]:ml-auto max-[760px]:flex">
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
            <span className="ml-auto grid h-5 min-w-5 place-items-center rounded-full bg-muted/80 px-1.5 text-[0.65rem] text-muted-foreground max-[760px]:hidden">
              {applicationCount}
            </span>
          </Button>
        </nav>
        <div className="mt-auto flex min-w-0 items-center gap-2.5 border-t border-sidebar-border/60 px-2 pt-3 pb-0.5 max-[760px]:hidden">
          <span className="grid size-[1.85rem] shrink-0 place-items-center rounded-[0.4rem] border border-border bg-card/75 text-muted-foreground [&_.icon]:size-3.5">
            <Icon name="server" />
          </span>
          <div className="min-w-0">
            <strong className="block truncate text-[0.72rem] font-medium">This device</strong>
            <span className="mt-px block truncate text-[0.61rem] text-muted-foreground">
              Managed by your organization
            </span>
          </div>
        </div>
      </aside>

      <main className="grid h-screen min-h-0 min-w-0 grid-rows-[4rem_minmax(0,1fr)] max-[760px]:h-auto max-[760px]:min-h-[calc(100vh-3.5rem)] max-[760px]:grid-rows-[auto_minmax(0,1fr)]">
        <header className="relative z-10 flex min-h-16 items-center justify-between gap-6 border-b border-border/70 bg-background/80 px-7 backdrop-blur-xl max-[760px]:px-4">
          <div>
            <h1 className="m-0 font-display text-[1.08rem] font-medium tracking-[-0.025em]">
              {page === 'overview' ? 'Device status' : 'Application management'}
            </h1>
          </div>
          <Button
            className="h-8 rounded-[0.38rem] border border-primary/75 px-3 text-[0.72rem] font-medium shadow-sm active:translate-y-px"
            disabled={syncing || !canSync}
            onClick={onSync}
          >
            <Icon name="sync" className={cn(syncing && 'animate-spin')} />
            {syncing ? 'Syncing…' : 'Sync now'}
          </Button>
        </header>
        <div className="min-h-0 overflow-y-auto [scrollbar-color:color-mix(in_oklch,var(--muted-foreground)_45%,transparent)_transparent] [scrollbar-width:thin] max-[760px]:overflow-visible">
          {children}
        </div>
      </main>
    </div>
  )
}
