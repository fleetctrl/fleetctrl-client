import type { ManagedApp, Overview } from '@/types'
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

  return (
    <div className="content desktop-overview">
      <section className="hero">
        <div className="hero-copy">
          <p className="hero-eyebrow">
            {overview ? 'Device policy is up to date' : 'Service connection interrupted'}
          </p>
          <p className="hero-time">
            {overview ? formatRelativeTime(overview.last_success?.completed_at) : 'Offline'}
          </p>
          <p className="hero-note">
            {overview
              ? 'The last sync completed without operator action.'
              : 'The client is waiting for the control service to become available.'}
          </p>
        </div>
        <div className="hero-footer">
          <span className={`service-state${overview ? ' online' : ''}`}>
            <i />
            {overview ? 'Service online' : 'Service offline'}
          </span>
          {overview && (
            <span className="hero-meta">
              {host(overview.server_url)} · agent v{overview.service_version}
            </span>
          )}
        </div>
      </section>

      <section className="native-group">
        <div className="section-label">
          <h3>Applications</h3>
          <span>{applications.length} managed</span>
        </div>
        <div className="summary-line">
          <div className="summary-ok">
            <strong>{installed}</strong><span>Installed</span><small>matches policy</small>
          </div>
          <div className={missing ? 'summary-warn' : ''}>
            <strong>{missing}</strong><span>Pending installation</span><small>requires reconciliation</small>
          </div>
          <div className={problems ? 'summary-danger' : ''}>
            <strong>{problems}</strong><span>Needs attention</span><small>processing errors</small>
          </div>
        </div>
      </section>

      <section className="native-group">
        <div className="section-label">
          <h3>Synchronization</h3>
          {overview?.current_run && <span>{statusText[overview.current_run.status]}</span>}
        </div>
        {overview?.current_run ? (
          <div className="run-row">
            <span className="spinner" />
            <div>
              <strong>{statusText[overview.current_run.kind] ?? 'Data synchronization'}</strong>
              <span>Started {formatTime(overview.current_run.started_at)}</span>
            </div>
          </div>
        ) : (
          <div className="idle-row">
            <span className="status-check"><Icon name="check" /></span>
            <div>
              <strong>Client is idle</strong>
              <span>Automatic checks will run according to the service schedule.</span>
            </div>
          </div>
        )}
        <dl className="property-list">
          <div>
            <dt>Last attempt</dt>
            <dd>
              {formatTime(overview?.last_attempt?.started_at ?? overview?.last_attempt?.created_at)}
              {overview?.last_attempt && <small>{statusText[overview.last_attempt.status]}</small>}
            </dd>
          </div>
          <div>
            <dt>Last successful sync</dt>
            <dd>{formatTime(overview?.last_success?.completed_at)}</dd>
          </div>
        </dl>
        {overview?.last_error?.error_message && (
          <div className="last-error">
            <Icon name="warning" />
            <div>
              <strong>Latest issue</strong>
              <span>{overview.last_error.error_message}</span>
            </div>
            <code>{overview.last_error.id.slice(0, 8)}</code>
          </div>
        )}
      </section>
    </div>
  )
}
