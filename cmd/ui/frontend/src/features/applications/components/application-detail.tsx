import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet'
import { formatTime } from '@/shared/lib/date'
import { statusText } from '@/shared/lib/status'
import type { AppEvent, ManagedApp } from '@/types'

import { applicationEventLabel, isOutcomeEvent } from '../model'

interface ApplicationDetailProps {
  application: ManagedApp
  events: AppEvent[]
  onClose: () => void
}

const maxVisibleEvents = 5

export function ApplicationDetail({
  application,
  events,
  onClose,
}: ApplicationDetailProps) {
  const visibleEvents = events.filter(event => isOutcomeEvent(event.event_type)).slice(0, maxVisibleEvents)
  return (
    <Sheet open onOpenChange={open => { if (!open) onClose() }}>
      <SheetContent className="w-full overflow-y-auto border-l-border bg-background p-5 shadow-xl sm:max-w-md">
        <div className="flex items-center gap-3 pt-1 pr-6 pb-4">
          <span className="grid size-10 shrink-0 place-items-center rounded-sm border border-border bg-muted text-sm font-medium text-muted-foreground">
            {application.display_name.slice(0, 1)}
          </span>
          <div>
            <span className="block text-[0.65rem] uppercase tracking-wider text-muted-foreground">Application details</span>
            <SheetTitle>{application.display_name}</SheetTitle>
            <SheetDescription>
              {application.publisher || application.installer_type} · {application.version}
            </SheetDescription>
          </div>
        </div>
        <div className="border-t border-border">
          <div className="flex min-h-10 items-center justify-between gap-4 border-b border-border py-2">
            <span className="text-xs text-muted-foreground">Requested state</span>
            <strong className="text-right text-xs">{application.desired_action === 'install' ? 'Install' : 'Uninstall'}</strong>
          </div>
          <div className="flex min-h-10 items-center justify-between gap-4 border-b border-border py-2">
            <span className="text-xs text-muted-foreground">Detected on device</span>
            <strong className="text-right text-xs">{statusText[application.detected_status]}</strong>
          </div>
          <div className="flex min-h-10 items-center justify-between gap-4 border-b border-border py-2">
            <span className="text-xs text-muted-foreground">Last verified</span>
            <strong className="text-right text-xs">{formatTime(application.last_checked_at)}</strong>
          </div>
          <div className="flex min-h-10 items-center justify-between gap-4 border-b border-border py-2">
            <span className="text-xs text-muted-foreground">Installed by client</span>
            <strong className="text-right text-xs">{formatTime(application.installed_by_client_at)}</strong>
          </div>
        </div>
        {application.last_error && (
          <div className="mt-4 rounded-sm border border-destructive/40 p-2.5 text-xs text-destructive">
            {application.last_error}
          </div>
        )}
        <div className="mt-5">
          <h3 className="mb-3 text-[0.65rem] font-medium uppercase tracking-wider text-muted-foreground">Recent events</h3>
          {visibleEvents.length === 0 ? (
            <p className="text-[0.7rem] text-muted-foreground">No events recorded yet.</p>
          ) : visibleEvents.map(event => (
            <div className="grid grid-cols-[0.5rem_1fr] gap-2.5 border-b border-border py-2" key={event.id}>
              <span className="mt-1.5 size-1.5 rounded-full bg-primary" />
              <div>
                <strong className="block text-[0.78rem]">{applicationEventLabel(event.event_type)}</strong>
                <small className="block text-[0.7rem] text-muted-foreground">{formatTime(event.created_at)} · {event.source}</small>
                {event.message && <p className="mt-1.5 mb-0 text-[0.7rem] text-muted-foreground">{event.message}</p>}
              </div>
            </div>
          ))}
        </div>
        <div className="mt-6 text-[0.7rem] text-muted-foreground">
          Release ID <code className="ml-1.5 text-foreground">{application.release_id}</code>
        </div>
        <p className="mt-4 mb-0 text-[0.7rem] leading-relaxed text-muted-foreground">
          “Detected on device” is based on detection rules. “Installed by client” is shown
          only when FleetCtrl performed and successfully verified the installation.
        </p>
      </SheetContent>
    </Sheet>
  )
}
