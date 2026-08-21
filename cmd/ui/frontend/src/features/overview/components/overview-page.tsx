import type { ManagedApp, Overview } from '@/types'
import { cn } from '@/lib/utils'
import { formatRelativeTime, formatTime } from '@/shared/lib/date'
import { statusText } from '@/shared/lib/status'

interface OverviewPageProps {
  overview?: Overview
  applications: ManagedApp[]
}

function host(url?: string) {
  return url ? url.replace(/^https?:\/\//, '').replace(/\/+$/, '') : ''
}

export function OverviewPage({ overview, applications }: OverviewPageProps) {
  const installed = applications.filter(app => app.detected_status === 'installed').length
  const problems = applications.filter(app => app.operation_status === 'error' || app.last_error).length
  const missing = applications.filter(app => app.detected_status === 'not_installed').length

  return (
    <div className="mx-auto w-full max-w-[62rem] px-5 pt-5 pb-10 max-[760px]:px-3 max-[760px]:pt-3 max-[760px]:pb-6">
      <section className="rounded-md border border-border bg-card">
        <div className="flex items-start justify-between gap-6 border-b border-border px-4 py-3.5 max-[760px]:flex-col max-[760px]:gap-3">
          <div>
            <h2 className="m-0 flex items-center gap-2.5 text-sm font-medium">
              <i className={cn('size-2 rounded-full', overview ? 'bg-success' : 'bg-destructive')} />
              {overview ? 'Everything looks good' : 'Service is unavailable'}
            </h2>
            <p className="mt-1 mb-0 max-w-[36rem] text-xs leading-relaxed text-muted-foreground">
              {overview
                ? 'This device matches its assigned policy and is communicating with FleetCtrl.'
                : 'FleetCtrl is waiting for the local service to become available.'}
            </p>
          </div>
          <div className="shrink-0 max-[760px]:w-full">
            <span className="block text-[0.65rem] uppercase tracking-wider text-muted-foreground">Last successful sync</span>
            <span className="mt-0.5 block text-xs">
              {overview ? formatRelativeTime(overview.last_success?.completed_at) : 'Not available'}
            </span>
          </div>
        </div>

        <div className="grid grid-cols-[9rem_repeat(3,minmax(0,1fr))] max-[760px]:grid-cols-1">
          <div className="border-r border-border px-4 py-3.5 max-[760px]:border-r-0 max-[760px]:border-b">
            <span className="block text-[0.65rem] uppercase tracking-wider text-muted-foreground">Managed</span>
            <strong className="mt-1 block text-lg">{applications.length}</strong>
          </div>
          <div className="border-r border-border px-4 py-3.5 max-[760px]:border-r-0 max-[760px]:border-b">
            <span className="block text-[0.65rem] uppercase tracking-wider text-muted-foreground">Installed</span>
            <strong className="mt-1 block text-lg">{installed}</strong>
          </div>
          <div className="border-r border-border px-4 py-3.5 max-[760px]:border-r-0 max-[760px]:border-b">
            <span className="block text-[0.65rem] uppercase tracking-wider text-muted-foreground">Not installed</span>
            <strong className={cn('mt-1 block text-lg', missing > 0 && 'text-warning')}>{missing}</strong>
          </div>
          <div className="px-4 py-3.5">
            <span className="block text-[0.65rem] uppercase tracking-wider text-muted-foreground">Needs attention</span>
            <strong className={cn('mt-1 block text-lg', problems > 0 && 'text-destructive')}>{problems}</strong>
          </div>
        </div>
      </section>

      <section className="mt-4 rounded-md border border-border bg-card">
        <div className="flex min-h-10 items-center justify-between gap-4 border-b border-border px-4">
          <h3 className="m-0 text-xs font-medium uppercase tracking-wider text-muted-foreground">Synchronization</h3>
          {overview?.current_run && (
            <span className="text-xs text-muted-foreground">
              {statusText[overview.current_run.status]}
            </span>
          )}
        </div>

        {overview?.current_run ? (
          <div className="flex items-center gap-3 px-4 py-3">
            <span className="size-4 animate-spin rounded-full border-2 border-muted border-t-primary" />
            <div>
              <strong className="block text-xs">{statusText[overview.current_run.kind] ?? 'Data synchronization'}</strong>
              <span className="mt-0.5 block text-xs text-muted-foreground">Started {formatTime(overview.current_run.started_at)}</span>
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-3 px-4 py-3">
            <i className={cn('ml-1 size-2 shrink-0 rounded-full', overview ? 'bg-success' : 'bg-muted-foreground/50')} />
            <div>
              <strong className="block text-xs">{overview ? 'Client is idle' : 'Waiting for service'}</strong>
              <span className="mt-0.5 block text-xs text-muted-foreground">
                Automatic checks run according to the service schedule.
              </span>
            </div>
          </div>
        )}

        <dl className="mx-4 mt-0 mb-3 border-t border-border">
          <div className="grid min-h-8 grid-cols-[11rem_1fr] items-center border-b border-border last:border-b-0 max-[760px]:grid-cols-1 max-[760px]:gap-0.5 max-[760px]:py-1.5">
            <dt className="text-xs text-muted-foreground">Last attempt</dt>
            <dd className="m-0 text-right text-xs max-[760px]:text-left">
              {formatTime(overview?.last_attempt?.started_at ?? overview?.last_attempt?.created_at)}
              {overview?.last_attempt && <span className="ml-2.5 text-muted-foreground">{statusText[overview.last_attempt.status]}</span>}
            </dd>
          </div>
          <div className="grid min-h-8 grid-cols-[11rem_1fr] items-center border-b border-border last:border-b-0 max-[760px]:grid-cols-1 max-[760px]:gap-0.5 max-[760px]:py-1.5">
            <dt className="text-xs text-muted-foreground">Last successful sync</dt>
            <dd className="m-0 text-right text-xs max-[760px]:text-left">{formatTime(overview?.last_success?.completed_at)}</dd>
          </div>
          {overview && (
            <>
              <div className="grid min-h-8 grid-cols-[11rem_1fr] items-center border-b border-border last:border-b-0 max-[760px]:grid-cols-1 max-[760px]:gap-0.5 max-[760px]:py-1.5">
                <dt className="text-xs text-muted-foreground">Management server</dt>
                <dd className="m-0 truncate text-right text-xs max-[760px]:text-left">{host(overview.server_url)}</dd>
              </div>
              <div className="grid min-h-8 grid-cols-[11rem_1fr] items-center border-b border-border last:border-b-0 max-[760px]:grid-cols-1 max-[760px]:gap-0.5 max-[760px]:py-1.5">
                <dt className="text-xs text-muted-foreground">Client version</dt>
                <dd className="m-0 text-right text-xs max-[760px]:text-left">{overview.service_version}</dd>
              </div>
            </>
          )}
        </dl>

        {overview?.last_error?.error_message && (
          <div className="mx-4 mb-3 flex items-center gap-2.5 rounded-sm border border-destructive/40 px-2.5 py-2 text-xs text-destructive">
            Latest issue: {overview.last_error.error_message}
            <code className="ml-auto opacity-70">{overview.last_error.id.slice(0, 8)}</code>
          </div>
        )}
      </section>
    </div>
  )
}
