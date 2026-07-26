import type { ReactNode } from 'react'

import { Button } from '@/components/ui/button'
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
  return (
    <div className="shell">
      <aside>
        <div className="brand">
          <div>
            <strong>FleetCtrl</strong>
            <span>Computer management</span>
          </div>
        </div>
        <nav>
          <Button
            variant="ghost"
            className={page === 'overview' ? 'active' : ''}
            onClick={() => onNavigate('overview')}
          >
            <Icon name="grid" />
            Overview
          </Button>
          <Button
            variant="ghost"
            className={page === 'applications' ? 'active' : ''}
            onClick={() => onNavigate('applications')}
          >
            <Icon name="apps" />
            Applications
            <span className="count">{applicationCount}</span>
          </Button>
        </nav>
      </aside>

      <main>
        <header>
          <div>
            <h1>{page === 'overview' ? 'Device status' : 'Application management'}</h1>
          </div>
          <Button
            className="sync-button"
            disabled={syncing || !canSync}
            onClick={onSync}
          >
            <Icon name="sync" />
            {syncing ? 'Sync in progress' : 'Sync now'}
          </Button>
        </header>
        {children}
      </main>
    </div>
  )
}
