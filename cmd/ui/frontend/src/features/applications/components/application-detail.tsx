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
      <SheetContent className="w-full overflow-y-auto p-5 sm:max-w-md">
        <div className="drawer-app">
          <span className="app-avatar large">{application.display_name.slice(0, 1)}</span>
          <div>
            <span className="eyebrow">Application details</span>
            <SheetTitle>{application.display_name}</SheetTitle>
            <SheetDescription>
              {application.publisher || application.installer_type} · {application.version}
            </SheetDescription>
          </div>
        </div>
        <div className="detail-grid">
          <div>
            <span>Requested state</span>
            <strong>{application.desired_action === 'install' ? 'Install' : 'Uninstall'}</strong>
          </div>
          <div>
            <span>Detected on device</span>
            <strong>{statusText[application.detected_status]}</strong>
          </div>
          <div>
            <span>Last verified</span>
            <strong>{formatTime(application.last_checked_at)}</strong>
          </div>
          <div>
            <span>Installed by client</span>
            <strong>{formatTime(application.installed_by_client_at)}</strong>
          </div>
        </div>
        {application.last_error && (
          <div className="detail-error">
            <Icon name="warning" />
            {application.last_error}
          </div>
        )}
        <div className="history">
          <h3>Recent events</h3>
          {events.length === 0 ? (
            <p className="muted">No events recorded yet.</p>
          ) : events.map(event => (
            <div className="event" key={event.id}>
              <span />
              <div>
                <strong>{applicationEventLabel(event.event_type)}</strong>
                <small>{formatTime(event.created_at)} · {event.source}</small>
                {event.message && <p>{event.message}</p>}
              </div>
            </div>
          ))}
        </div>
        <div className="diagnostic">
          Release ID <code>{application.release_id}</code>
        </div>
        <p className="explanation">
          “Detected on device” is based on detection rules. “Installed by client” is shown
          only when FleetCtrl performed and successfully verified the installation.
        </p>
      </SheetContent>
    </Sheet>
  )
}
