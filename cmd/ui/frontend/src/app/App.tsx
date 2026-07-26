import { useState } from 'react'

import { ApplicationsPage } from '@/features/applications/components/applications-page'
import { OverviewPage } from '@/features/overview/components/overview-page'
import { useFleetData } from '@/shared/hooks/use-fleet-data'

import { AppShell, type Page } from './components/app-shell'
import { ServiceError } from './components/service-error'

export default function App() {
  const [page, setPage] = useState<Page>('overview')
  const {
    applications,
    error,
    loading,
    overview,
    refresh,
    syncing,
    triggerSync,
  } = useFleetData()

  return (
    <AppShell
      page={page}
      applicationCount={applications.length}
      canSync={Boolean(overview)}
      syncing={syncing}
      onNavigate={setPage}
      onSync={() => void triggerSync()}
    >
      {error && <ServiceError message={error} onRetry={() => void refresh()} />}

      {loading ? (
        <div className="flex min-h-72 items-center justify-center gap-1.5">
          <span className="size-1.5 animate-pulse rounded-full bg-muted-foreground" />
          <span className="size-1.5 animate-pulse rounded-full bg-muted-foreground [animation-delay:150ms]" />
          <span className="size-1.5 animate-pulse rounded-full bg-muted-foreground [animation-delay:300ms]" />
        </div>
      ) : page === 'overview' ? (
        <OverviewPage overview={overview} applications={applications} />
      ) : (
        <ApplicationsPage applications={applications} />
      )}
    </AppShell>
  )
}
