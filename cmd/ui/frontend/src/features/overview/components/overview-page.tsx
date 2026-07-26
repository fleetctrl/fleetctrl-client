import type { ManagedApp, Overview } from '@/types'
import { cn } from '@/lib/utils'
import { Icon } from '@/shared/components/icon'
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
  const panel = 'overflow-hidden rounded-[0.55rem] border border-border/90 bg-card shadow-sm backdrop-blur-lg motion-safe:animate-panel-enter'
  const sectionHeader = 'flex min-h-[3.65rem] items-center justify-between gap-4 border-b border-border px-[1.1rem] py-3'
  const summaryItem = 'flex min-w-0 items-center gap-3 border-r border-border px-[1.1rem] py-3.5 transition-colors duration-150 last:border-r-0 hover:bg-muted/30'
  const summaryIcon = 'grid size-8 shrink-0 place-items-center rounded-[0.42rem] bg-emerald-500/10 text-emerald-600 [&_svg]:size-4'
  const propertyRow = 'grid min-h-10 grid-cols-[11rem_1fr] items-center border-b border-border py-2 last:border-b-0 max-[760px]:grid-cols-1 max-[760px]:gap-1'

  return (
    <div className="mx-auto grid w-full max-w-[62rem] gap-4 px-7 pt-6 pb-10 motion-safe:animate-page-enter max-[760px]:px-3 max-[760px]:pt-4 max-[760px]:pb-6">
      <section className={cn(panel, 'relative grid min-h-[9.8rem] grid-cols-[minmax(0,1fr)_13.5rem] items-center gap-5 border-l-[0.22rem] border-l-emerald-500 px-6 py-5 max-[760px]:grid-cols-1')}>
        <div>
          <p className="m-0 text-[0.66rem] font-medium text-muted-foreground">Device status</p>
          <h2 className="mt-1 mb-0 font-display text-[1.35rem] font-medium tracking-[-0.025em]">
            {overview ? 'Everything looks good' : 'Service is unavailable'}
          </h2>
          <p className="mt-1.5 mb-0 max-w-[31rem] text-[0.74rem] leading-5 text-muted-foreground">
            {overview
              ? 'This device matches its assigned policy and is communicating with FleetCtrl.'
              : 'FleetCtrl is waiting for the local service to become available.'}
          </p>
        </div>
        <div className="min-w-0 border-l border-border pl-5 max-[760px]:border-t max-[760px]:border-l-0 max-[760px]:pt-3 max-[760px]:pl-0">
          <span className="block text-[0.64rem] text-muted-foreground">Last successful sync</span>
          <strong className="mt-1 block font-mono text-[0.88rem] font-medium">
            {overview ? formatRelativeTime(overview.last_success?.completed_at) : 'Not available'}
          </strong>
          <span className="mt-3 inline-flex items-center gap-2 text-[0.68rem]">
            <i className={cn('size-[0.45rem] rounded-full', overview ? 'bg-emerald-500' : 'bg-destructive')} />
            {overview ? 'Service online' : 'Service offline'}
          </span>
        </div>
      </section>

      <section className={cn(panel, 'motion-safe:[animation-delay:60ms]')}>
        <div className={sectionHeader}>
          <div>
            <h3 className="m-0 font-display text-[0.82rem] font-medium">Applications</h3>
            <p className="mt-0.5 mb-0 text-[0.65rem] text-muted-foreground">Current state on this device</p>
          </div>
          <span className="rounded-full bg-muted px-2 py-1 text-[0.6rem] font-medium text-muted-foreground">
            {applications.length} managed
          </span>
        </div>
        <div className="grid grid-cols-3 max-[760px]:grid-cols-1">
          <div className={summaryItem}>
            <span className={summaryIcon}><Icon name="check" /></span>
            <span>
              <strong className="block font-mono text-base font-medium leading-none">{installed}</strong>
              <small className="mt-1 block whitespace-nowrap text-[0.66rem] text-muted-foreground">Installed</small>
            </span>
          </div>
          <div className={summaryItem}>
            <span className={cn(summaryIcon, missing && 'bg-amber-500/15 text-amber-500')}><Icon name="clock" /></span>
            <span>
              <strong className="block font-mono text-base font-medium leading-none">{missing}</strong>
              <small className="mt-1 block whitespace-nowrap text-[0.66rem] text-muted-foreground">Pending installation</small>
            </span>
          </div>
          <div className={summaryItem}>
            <span className={cn(summaryIcon, problems && 'bg-destructive/10 text-destructive')}><Icon name="warning" /></span>
            <span>
              <strong className="block font-mono text-base font-medium leading-none">{problems}</strong>
              <small className="mt-1 block whitespace-nowrap text-[0.66rem] text-muted-foreground">Needs attention</small>
            </span>
          </div>
        </div>
      </section>

      <section className={cn(panel, 'motion-safe:[animation-delay:120ms]')}>
        <div className={sectionHeader}>
          <div>
            <h3 className="m-0 font-display text-[0.82rem] font-medium">Synchronization</h3>
            <p className="mt-0.5 mb-0 text-[0.65rem] text-muted-foreground">Service activity and connection details</p>
          </div>
          {overview?.current_run && (
            <span className="rounded-full bg-muted px-2 py-1 text-[0.6rem] font-medium text-muted-foreground">
              {statusText[overview.current_run.status]}
            </span>
          )}
        </div>
        {overview?.current_run ? (
          <div className="flex min-h-16 items-center gap-3 px-[1.1rem] py-3">
            <span className="size-6 animate-spin rounded-full border-2 border-border border-t-primary" />
            <div>
              <strong className="block text-[0.8rem]">{statusText[overview.current_run.kind] ?? 'Data synchronization'}</strong>
              <span className="mt-0.5 block text-[0.75rem] text-muted-foreground">Started {formatTime(overview.current_run.started_at)}</span>
            </div>
          </div>
        ) : (
          <div className="flex min-h-16 items-center gap-3 px-[1.1rem] py-3">
            <span className="grid size-8 shrink-0 place-items-center rounded-[0.45rem] bg-emerald-500/15 text-emerald-500">
              <Icon name="check" />
            </span>
            <div>
              <strong className="block text-[0.8rem]">Client is idle</strong>
              <span className="mt-0.5 block text-[0.75rem] text-muted-foreground">Automatic checks will run according to the service schedule.</span>
            </div>
          </div>
        )}
        <dl className="mx-[1.1rem] mt-0 mb-4 border-t border-border">
          <div className={propertyRow}>
            <dt className="text-[0.7rem] text-muted-foreground">Last attempt</dt>
            <dd className="m-0 text-right font-mono text-[0.67rem] max-[760px]:text-left">
              {formatTime(overview?.last_attempt?.started_at ?? overview?.last_attempt?.created_at)}
              {overview?.last_attempt && <small className="ml-2.5 text-muted-foreground">{statusText[overview.last_attempt.status]}</small>}
            </dd>
          </div>
          <div className={propertyRow}>
            <dt className="text-[0.7rem] text-muted-foreground">Last successful sync</dt>
            <dd className="m-0 text-right font-mono text-[0.67rem] max-[760px]:text-left">{formatTime(overview?.last_success?.completed_at)}</dd>
          </div>
          {overview && (
            <>
              <div className={propertyRow}>
                <dt className="text-[0.7rem] text-muted-foreground">Management server</dt>
                <dd className="m-0 text-right font-mono text-[0.67rem] max-[760px]:text-left">{host(overview.server_url)}</dd>
              </div>
              <div className={propertyRow}>
                <dt className="text-[0.7rem] text-muted-foreground">Client version</dt>
                <dd className="m-0 text-right font-mono text-[0.67rem] max-[760px]:text-left">{overview.service_version}</dd>
              </div>
            </>
          )}
        </dl>
        {overview?.last_error?.error_message && (
          <div className="mx-[1.1rem] mb-4 flex items-center gap-2.5 rounded-md border border-destructive/35 bg-destructive/10 p-2.5 text-destructive">
            <Icon name="warning" />
            <div className="flex-1">
              <strong className="block text-xs">Latest issue</strong>
              <span className="block text-xs">{overview.last_error.error_message}</span>
            </div>
            <code className="text-[0.7rem]">{overview.last_error.id.slice(0, 8)}</code>
          </div>
        )}
      </section>
    </div>
  )
}
