import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet'
import { Icon } from '@/shared/components/icon'
import { formatTime } from '@/shared/lib/date'
import { statusText } from '@/shared/lib/status'
import type { AppEvent, ManagedApp } from '@/types'

import { applicationEventLabel } from '../model'

interface ApplicationDetailProps {
  application: ManagedApp
  events: AppEvent[]
  onClose: () => void
}

export function ApplicationDetail({
  application,
  events,
  onClose,
}: ApplicationDetailProps) {
  return (
    <Sheet open onOpenChange={open => { if (!open) onClose() }}>
      <SheetContent className="w-full overflow-y-auto border-l-border bg-background/95 p-5 shadow-[-12px_0_40px_oklch(0.2_0.03_255/16%)] backdrop-blur-2xl sm:max-w-md">
        <div className="flex items-center gap-3.5 pt-1 pr-6 pb-4">
          <span className="grid size-12 shrink-0 place-items-center rounded-lg border border-border bg-primary/10 text-base font-bold text-primary">
            {application.display_name.slice(0, 1)}
          </span>
          <div>
            <span className="text-[0.66rem] font-medium text-muted-foreground">Application details</span>
            <SheetTitle>{application.display_name}</SheetTitle>
            <SheetDescription>
              {application.publisher || application.installer_type} · {application.version}
            </SheetDescription>
          </div>
        </div>
        <div className="border-t border-border">
          <div className="flex min-h-13 items-center justify-between gap-4 border-b border-border py-2">
            <span className="text-xs text-muted-foreground">Requested state</span>
            <strong className="text-right text-[0.8rem] font-medium">{application.desired_action === 'install' ? 'Install' : 'Uninstall'}</strong>
          </div>
          <div className="flex min-h-13 items-center justify-between gap-4 border-b border-border py-2">
            <span className="text-xs text-muted-foreground">Detected on device</span>
            <strong className="text-right text-[0.8rem] font-medium">{statusText[application.detected_status]}</strong>
          </div>
          <div className="flex min-h-13 items-center justify-between gap-4 border-b border-border py-2">
            <span className="text-xs text-muted-foreground">Last verified</span>
            <strong className="text-right font-mono text-[0.75rem] font-medium">{formatTime(application.last_checked_at)}</strong>
          </div>
          <div className="flex min-h-13 items-center justify-between gap-4 border-b border-border py-2">
            <span className="text-xs text-muted-foreground">Installed by client</span>
            <strong className="text-right font-mono text-[0.75rem] font-medium">{formatTime(application.installed_by_client_at)}</strong>
          </div>
        </div>
        {application.last_error && (
          <div className="mt-4 flex items-center gap-2.5 rounded-md border border-destructive/35 bg-destructive/10 p-2.5 text-xs text-destructive">
            <Icon name="warning" />
            {application.last_error}
          </div>
        )}
        <div className="mt-5">
          <h3 className="mb-3 text-[0.85rem] font-semibold">Recent events</h3>
          {events.length === 0 ? (
            <p className="text-[0.7rem] text-muted-foreground">No events recorded yet.</p>
          ) : events.map(event => (
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
