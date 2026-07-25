import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from './backend'
import type { AppEvent, ManagedApp, Overview } from './types'
import { Button } from '@/components/ui/button'
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ApplicationsDataTable } from '@/components/applications-data-table'

type Page = 'overview' | 'applications'
type Filter = 'all' | 'installed' | 'not_installed' | 'error' | 'working'

const statusText: Record<string, string> = {
  queued: 'Queued', running: 'Running', success: 'Successful', partial: 'Partially successful',
  error: 'Error', interrupted: 'Interrupted', installed: 'Installed',
  not_installed: 'Not installed', unknown: 'Unknown', idle: 'Idle',
  installing: 'Installing', uninstalling: 'Uninstalling', upgrading: 'Upgrading'
}

const formatTime = (value?: string) => value
  ? new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
  : 'Not yet'

const relTime = (value?: string) => {
  if (!value) return 'Not yet'
  const diff = Date.now() - new Date(value).getTime()
  if (diff < 45_000) return 'just now'
  const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' })
  const minutes = Math.round(diff / 60_000)
  if (minutes < 60) return rtf.format(-minutes, 'minute')
  const hours = Math.round(minutes / 60)
  if (hours < 24) return rtf.format(-hours, 'hour')
  return rtf.format(-Math.round(hours / 24), 'day')
}

const host = (url?: string) => url ? url.replace(/^https?:\/\//, '').replace(/\/+$/, '') : ''

function Icon({ name }: { name: 'grid' | 'apps' | 'sync' | 'check' | 'warning' | 'server' | 'clock' | 'close' }) {
  const paths = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/></>,
    apps: <><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M4 9h16M9 9v11"/></>,
    sync: <><path d="M20 7h-5V2"/><path d="M20 7a8 8 0 1 0 1 8"/></>,
    check: <path d="m5 12 4 4L19 6"/>,
    warning: <><path d="M12 3 2.8 20h18.4L12 3Z"/><path d="M12 9v4M12 17h.01"/></>,
    server: <><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/></>,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
    close: <path d="m6 6 12 12M18 6 6 18"/>
  }
  return <svg aria-hidden="true" className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{paths[name]}</svg>
}

export default function App() {
  const [page, setPage] = useState<Page>('overview')
  const [overview, setOverview] = useState<Overview>()
  const [applications, setApplications] = useState<ManagedApp[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [filter, setFilter] = useState<Filter>('all')
  const [selected, setSelected] = useState<ManagedApp>()
  const [events, setEvents] = useState<AppEvent[]>([])

  const refresh = useCallback(async () => {
    try {
      const next = await api.overview()
      setOverview(next)
      setError('')
      setSyncing(Boolean(next.current_run))
      const apps = await api.applications()
      setApplications(apps ?? [])
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
      setOverview(undefined)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
    const delay = overview?.current_run ? 1000 : overview ? 30000 : 5000
    const timer = window.setInterval(() => void refresh(), delay)
    return () => window.clearInterval(timer)
  }, [refresh, overview?.current_run?.id, Boolean(overview)])

  const triggerSync = async () => {
    setSyncing(true)
    try {
      await api.triggerSync()
      await refresh()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
      setSyncing(false)
    }
  }

  const showDetail = async (app: ManagedApp) => {
    setSelected(app)
    setEvents([])
    try { setEvents((await api.events(app.release_id)) ?? []) } catch { setEvents([]) }
  }

  const filtered = useMemo(() => applications.filter(app => {
    if (filter === 'all') return true
    if (filter === 'error') return app.operation_status === 'error' || Boolean(app.last_error)
    if (filter === 'working') return !['idle', 'error'].includes(app.operation_status)
    return app.detected_status === filter
  }), [applications, filter])

  return <div className="shell">
    <aside>
      <div className="brand"><div><strong>FleetCtrl</strong><span>Computer management</span></div></div>
      <nav>
        <Button variant="ghost" className={page === 'overview' ? 'active' : ''} onClick={() => setPage('overview')}><Icon name="grid"/>Overview</Button>
        <Button variant="ghost" className={page === 'applications' ? 'active' : ''} onClick={() => setPage('applications')}><Icon name="apps"/>Applications<span className="count">{applications.length}</span></Button>
      </nav>
    </aside>

    <main>
      <header><div><h1>{page === 'overview' ? 'Device status' : 'Application management'}</h1></div>
        <Button className="sync-button" disabled={syncing || !overview} onClick={triggerSync}><Icon name="sync"/>{syncing ? 'Sync in progress' : 'Sync now'}</Button>
      </header>

      {error && <div className="alert"><Icon name="warning"/><div><strong>FleetCtrl service is unavailable</strong><span>{error}</span></div><Button variant="destructive" size="sm" onClick={() => void refresh()}>Try again</Button></div>}
      {loading ? <div className="loading"><span/><span/><span/></div> : page === 'overview'
        ? <OverviewPage overview={overview} apps={applications}/>
        : <ApplicationsPage apps={filtered} filter={filter} setFilter={setFilter} onSelect={showDetail}/>}
    </main>

    {selected && <AppDetail app={selected} events={events} close={() => setSelected(undefined)}/>}
  </div>
}

function OverviewPage({ overview, apps }: { overview?: Overview, apps: ManagedApp[] }) {
  const installed = apps.filter(app => app.detected_status === 'installed').length
  const problems = apps.filter(app => app.operation_status === 'error' || app.last_error).length
  const missing = apps.filter(app => app.detected_status === 'not_installed').length
  return <div className="content desktop-overview">
    <section className="hero">
      <div className="hero-copy">
        <p className="hero-eyebrow">{overview ? 'Device policy is up to date' : 'Service connection interrupted'}</p>
        <p className="hero-time">{overview ? relTime(overview.last_success?.completed_at) : 'Offline'}</p>
        <p className="hero-note">{overview ? 'The last sync completed without operator action.' : 'The client is waiting for the control service to become available.'}</p>
      </div>
      <div className="hero-footer">
        <span className={`service-state${overview ? ' online' : ''}`}><i/>{overview ? 'Service online' : 'Service offline'}</span>
        {overview && <span className="hero-meta">{host(overview.server_url)} · agent v{overview.service_version}</span>}
      </div>
    </section>

    <section className="native-group">
      <div className="section-label"><h3>Applications</h3><span>{apps.length} managed</span></div>
      <div className="summary-line">
        <div className="summary-ok"><strong>{installed}</strong><span>Installed</span><small>matches policy</small></div>
        <div className={missing ? 'summary-warn' : ''}><strong>{missing}</strong><span>Pending installation</span><small>requires reconciliation</small></div>
        <div className={problems ? 'summary-danger' : ''}><strong>{problems}</strong><span>Needs attention</span><small>processing errors</small></div>
      </div>
    </section>

    <section className="native-group">
      <div className="section-label"><h3>Synchronization</h3>{overview?.current_run && <span>{statusText[overview.current_run.status]}</span>}</div>
      {overview?.current_run
        ? <div className="run-row"><span className="spinner"/><div><strong>{statusText[overview.current_run.kind] ?? 'Data synchronization'}</strong><span>Started {formatTime(overview.current_run.started_at)}</span></div></div>
        : <div className="idle-row"><span className="status-check"><Icon name="check"/></span><div><strong>Client is idle</strong><span>Automatic checks will run according to the service schedule.</span></div></div>}
      <dl className="property-list">
        <div><dt>Last attempt</dt><dd>{formatTime(overview?.last_attempt?.started_at ?? overview?.last_attempt?.created_at)}{overview?.last_attempt && <small>{statusText[overview.last_attempt.status]}</small>}</dd></div>
        <div><dt>Last successful sync</dt><dd>{formatTime(overview?.last_success?.completed_at)}</dd></div>
      </dl>
      {overview?.last_error?.error_message && <div className="last-error"><Icon name="warning"/><div><strong>Latest issue</strong><span>{overview.last_error.error_message}</span></div><code>{overview.last_error.id.slice(0, 8)}</code></div>}
    </section>
  </div>
}

function ApplicationsPage({ apps, filter, setFilter, onSelect }: { apps: ManagedApp[], filter: Filter, setFilter: (f: Filter) => void, onSelect: (app: ManagedApp) => void }) {
  const filters: [Filter, string][] = [['all','All'], ['installed','Installed'], ['not_installed','Not installed'], ['error','Error'], ['working','In progress']]
  return <div className="content">
    <div className="applications-toolbar"><p>The requested state is compared with what the client found on this device.</p><Tabs value={filter} onValueChange={value => setFilter(value as Filter)} className="max-w-full"><TabsList className="h-auto max-w-full justify-start overflow-x-auto">{filters.map(([key, text]) => <TabsTrigger key={key} value={key}>{text}</TabsTrigger>)}</TabsList></Tabs></div>
    <ApplicationsDataTable data={apps} onSelect={onSelect}/>
  </div>
}

function AppDetail({ app, events, close }: { app: ManagedApp, events: AppEvent[], close: () => void }) {
  return <Sheet open onOpenChange={open => { if (!open) close() }}><SheetContent className="w-full overflow-y-auto p-5 sm:max-w-md">
    <div className="drawer-app"><span className="app-avatar large">{app.display_name.slice(0, 1)}</span><div><span className="eyebrow">Application details</span><SheetTitle>{app.display_name}</SheetTitle><SheetDescription>{app.publisher || app.installer_type} · {app.version}</SheetDescription></div></div>
    <div className="detail-grid"><div><span>Requested state</span><strong>{app.desired_action === 'install' ? 'Install' : 'Uninstall'}</strong></div><div><span>Detected on device</span><strong>{statusText[app.detected_status]}</strong></div><div><span>Last verified</span><strong>{formatTime(app.last_checked_at)}</strong></div><div><span>Installed by client</span><strong>{formatTime(app.installed_by_client_at)}</strong></div></div>
    {app.last_error && <div className="detail-error"><Icon name="warning"/>{app.last_error}</div>}
    <div className="history"><h3>Recent events</h3>{events.length === 0 ? <p className="muted">No events recorded yet.</p> : events.map(event => <div className="event" key={event.id}><span/><div><strong>{eventLabel(event.event_type)}</strong><small>{formatTime(event.created_at)} · {event.source}</small>{event.message && <p>{event.message}</p>}</div></div>)}</div>
    <div className="diagnostic">Release ID <code>{app.release_id}</code></div>
    <p className="explanation">“Detected on device” is based on detection rules. “Installed by client” is shown only when FleetCtrl performed and successfully verified the installation.</p>
  </SheetContent></Sheet>
}

function eventLabel(type: string) {
  const labels: Record<string, string> = { assigned: 'Application assigned', assignment_changed: 'Assignment changed', detection_installed: 'Installation detected', detection_not_installed: 'Installation not detected', install_started: 'Installation started', install_succeeded: 'Installation completed', install_failed: 'Installation failed', uninstall_started: 'Uninstallation started', uninstall_succeeded: 'Uninstallation completed', uninstall_failed: 'Uninstallation failed', upgrade_started: 'Upgrade started', upgrade_succeeded: 'Upgrade completed', upgrade_failed: 'Upgrade failed' }
  return labels[type] || type
}
