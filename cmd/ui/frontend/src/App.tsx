import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from './backend'
import type { AppEvent, ManagedApp, Overview } from './types'

type Page = 'overview' | 'applications'
type Filter = 'all' | 'installed' | 'not_installed' | 'error' | 'working'

const statusText: Record<string, string> = {
  queued: 'Čeká', running: 'Probíhá', success: 'Úspěch', partial: 'Částečný úspěch',
  error: 'Chyba', interrupted: 'Přerušeno', installed: 'Nainstalováno',
  not_installed: 'Nenainstalováno', unknown: 'Neznámý', idle: 'V klidu',
  installing: 'Instaluje se', uninstalling: 'Odinstalovává se', upgrading: 'Aktualizuje se'
}

const formatTime = (value?: string) => value
  ? new Intl.DateTimeFormat('cs-CZ', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
  : 'Zatím neproběhlo'

const relTime = (value?: string) => {
  if (!value) return 'Zatím neproběhla'
  const diff = Date.now() - new Date(value).getTime()
  if (diff < 45_000) return 'právě teď'
  const rtf = new Intl.RelativeTimeFormat('cs', { numeric: 'auto' })
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
      <div className="brand"><div className="brand-mark">F</div><div><strong>FleetCtrl</strong><span>Správa zařízení</span></div></div>
      <nav>
        <button className={page === 'overview' ? 'active' : ''} onClick={() => setPage('overview')}><Icon name="grid"/>Přehled</button>
        <button className={page === 'applications' ? 'active' : ''} onClick={() => setPage('applications')}><Icon name="apps"/>Aplikace<span className="count">{applications.length}</span></button>
      </nav>
      <div className="aside-status">
        <span className={`dot ${overview ? 'online' : ''}`}/>
        <div>
          <strong>{overview ? 'Služba je dostupná' : 'Služba je nedostupná'}</strong>
          <span className="aside-meta">{overview ? `${overview.service_version} · ${host(overview.server_url)}` : 'čekám na připojení'}</span>
        </div>
      </div>
    </aside>

    <main>
      <header><div><p>FleetCtrl Client</p><h1>{page === 'overview' ? 'Stav zařízení' : 'Aplikace'}</h1></div>
        <button className="sync-button" disabled={syncing || !overview} onClick={triggerSync}><Icon name="sync"/>{syncing ? 'Synchronizace probíhá' : 'Synchronizovat nyní'}</button>
      </header>

      {error && <div className="alert"><Icon name="warning"/><div><strong>Služba FleetCtrl není dostupná</strong><span>{error}</span></div><button onClick={() => void refresh()}>Zkusit znovu</button></div>}
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
      <p className="hero-eyebrow">{overview ? 'Poslední úspěšná synchronizace' : 'Stav služby FleetCtrl'}</p>
      <p className="hero-time">{overview ? relTime(overview.last_success?.completed_at) : 'Nedostupná'}</p>
      <p className="hero-status">
        <span className={`pulse-dot${overview ? '' : ' down'}`}/>
        {overview ? 'Služba je připojená' : 'Služba neodpovídá'}
        {overview && <span className="hero-meta">{host(overview.server_url)} · v{overview.service_version}</span>}
      </p>
    </section>

    <section className="native-group">
      <div className="section-label"><h3>Aplikace</h3><span>{apps.length} spravovaných</span></div>
      <div className="summary-line">
        <div><strong>{installed}</strong><span>Nainstalováno</span></div>
        <div><strong>{missing}</strong><span>Chybí</span></div>
        <div><strong>{problems}</strong><span>Chyby</span></div>
      </div>
    </section>

    <section className="native-group">
      <div className="section-label"><h3>Synchronizace</h3>{overview?.current_run && <span>{statusText[overview.current_run.status]}</span>}</div>
      {overview?.current_run
        ? <div className="run-row"><span className="spinner"/><div><strong>{statusText[overview.current_run.kind] ?? 'Synchronizace dat'}</strong><span>Spuštěno {formatTime(overview.current_run.started_at)}</span></div></div>
        : <div className="idle-row"><span className="status-check"><Icon name="check"/></span><div><strong>Klient je v klidu</strong><span>Automatická kontrola poběží podle plánu služby.</span></div></div>}
      <dl className="property-list">
        <div><dt>Poslední pokus</dt><dd>{formatTime(overview?.last_attempt?.started_at ?? overview?.last_attempt?.created_at)}{overview?.last_attempt && <small>{statusText[overview.last_attempt.status]}</small>}</dd></div>
        <div><dt>Poslední úspěch</dt><dd>{formatTime(overview?.last_success?.completed_at)}</dd></div>
      </dl>
      {overview?.last_error?.error_message && <div className="last-error"><Icon name="warning"/><div><strong>Poslední problém</strong><span>{overview.last_error.error_message}</span></div><code>{overview.last_error.id.slice(0, 8)}</code></div>}
    </section>
  </div>
}

function ApplicationsPage({ apps, filter, setFilter, onSelect }: { apps: ManagedApp[], filter: Filter, setFilter: (f: Filter) => void, onSelect: (app: ManagedApp) => void }) {
  const filters: [Filter, string][] = [['all','Všechny'], ['installed','Nainstalované'], ['not_installed','Nenainstalované'], ['error','Chyba'], ['working','Zpracovává se']]
  return <div className="content">
    <div className="filters">{filters.map(([key, text]) => <button key={key} className={filter === key ? 'active' : ''} onClick={() => setFilter(key)}>{text}</button>)}</div>
    <section className="app-table">
      <div className="table-head"><span>Aplikace</span><span>Požadavek</span><span>Stav v zařízení</span><span>Poslední kontrola</span><span/></div>
      {apps.length === 0
        ? <div className="empty-apps"><div className="soft-icon"><Icon name="apps"/></div><h3>Žádné aplikace k zobrazení</h3><p>Po synchronizaci se zde objeví aplikace přiřazené tomuto zařízení.</p></div>
        : apps.map(app => <button className="app-row" key={app.release_id} onClick={() => onSelect(app)}>
          <span className="app-name"><span className="app-avatar">{app.display_name.slice(0, 1).toUpperCase()}</span><span><strong>{app.display_name}</strong><small>{app.publisher || app.installer_type} · {app.version || 'bez verze'}</small></span></span>
          <span><span className="action">{app.desired_action === 'install' ? 'Nainstalovat' : 'Odinstalovat'}</span></span>
          <span><span className={`state ${app.detected_status}`}>{statusText[app.detected_status]}</span>{app.operation_status !== 'idle' && <small>{statusText[app.operation_status]}</small>}</span>
          <span className="checked">{formatTime(app.last_checked_at)}</span><span className="chevron">›</span>
        </button>)}
    </section>
  </div>
}

function AppDetail({ app, events, close }: { app: ManagedApp, events: AppEvent[], close: () => void }) {
  return <div className="drawer-backdrop" onMouseDown={close}><aside aria-label={`Detail aplikace ${app.display_name}`} aria-modal="true" role="dialog" className="drawer" onMouseDown={e => e.stopPropagation()}>
    <button aria-label="Zavřít detail aplikace" className="drawer-close" onClick={close}><Icon name="close"/></button>
    <div className="drawer-app"><span className="app-avatar large">{app.display_name.slice(0, 1)}</span><div><span className="eyebrow">Detail aplikace</span><h2>{app.display_name}</h2><p>{app.publisher || app.installer_type} · {app.version}</p></div></div>
    <div className="detail-grid"><div><span>Požadovaný stav</span><strong>{app.desired_action === 'install' ? 'Nainstalovat' : 'Odinstalovat'}</strong></div><div><span>Nalezeno v systému</span><strong>{statusText[app.detected_status]}</strong></div><div><span>Naposledy ověřeno</span><strong>{formatTime(app.last_checked_at)}</strong></div><div><span>Instalováno klientem</span><strong>{formatTime(app.installed_by_client_at)}</strong></div></div>
    {app.last_error && <div className="detail-error"><Icon name="warning"/>{app.last_error}</div>}
    <div className="history"><h3>Poslední události</h3>{events.length === 0 ? <p className="muted">Zatím bez zaznamenaných událostí.</p> : events.map(event => <div className="event" key={event.id}><span/><div><strong>{eventLabel(event.event_type)}</strong><small>{formatTime(event.created_at)} · {event.source}</small>{event.message && <p>{event.message}</p>}</div></div>)}</div>
    <div className="diagnostic">Release ID <code>{app.release_id}</code></div>
    <p className="explanation">„Nalezeno v systému“ vychází z detekčních pravidel. Čas „Instalováno klientem“ se zobrazí pouze tehdy, když instalaci provedl FleetCtrl a následně ji úspěšně ověřil.</p>
  </aside></div>
}

function eventLabel(type: string) {
  const labels: Record<string, string> = { assigned: 'Aplikace přiřazena', assignment_changed: 'Přiřazení změněno', detection_installed: 'Instalace nalezena', detection_not_installed: 'Instalace nenalezena', install_started: 'Instalace zahájena', install_succeeded: 'Instalace dokončena', install_failed: 'Instalace selhala', uninstall_started: 'Odinstalace zahájena', uninstall_succeeded: 'Odinstalace dokončena', uninstall_failed: 'Odinstalace selhala', upgrade_started: 'Aktualizace zahájena', upgrade_succeeded: 'Aktualizace dokončena', upgrade_failed: 'Aktualizace selhala' }
  return labels[type] || type
}
