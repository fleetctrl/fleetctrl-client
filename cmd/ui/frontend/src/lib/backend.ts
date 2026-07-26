import type { AppEvent, ManagedApp, Overview, SyncRun } from '../types'

function backend() {
  const api = window.go?.main?.UIBackend
  if (!api && import.meta.env.DEV) return demoBackend
  if (!api) throw new Error('The UI service is not ready.')
  return api
}

const now = new Date()
const minutesAgo = (minutes: number) => new Date(now.getTime() - minutes * 60_000).toISOString()
const demoApps: ManagedApp[] = [
  { release_id: 'rel-office', app_id: 'office', display_name: 'Microsoft 365 Apps', publisher: 'Microsoft', version: '16.0', installer_type: 'win32', assign_type: 'include', desired_action: 'install', detected_status: 'installed', operation_status: 'idle', last_checked_at: minutesAgo(4), installed_by_client_at: minutesAgo(8640) },
  { release_id: 'rel-rustdesk', app_id: 'rustdesk', display_name: 'RustDesk', publisher: 'RustDesk', version: '1.3.8', installer_type: 'winget', assign_type: 'include', desired_action: 'install', detected_status: 'installed', operation_status: 'idle', last_checked_at: minutesAgo(4) },
  { release_id: 'rel-vlc', app_id: 'vlc', display_name: 'VLC media player', publisher: 'VideoLAN', version: '3.0.21', installer_type: 'winget', assign_type: 'include', desired_action: 'install', detected_status: 'not_installed', operation_status: 'idle', last_checked_at: minutesAgo(4) }
]
const demoOverview: Overview = {
  service_available: true, service_version: '2.0.2', server_url: 'https://fleet.example.cz',
  checked_at: now.toISOString(),
  last_attempt: { id: 'run-demo', kind: 'full', trigger: 'automatic', status: 'success', started_at: minutesAgo(4), completed_at: minutesAgo(4), created_at: minutesAgo(4) },
  last_success: { id: 'run-demo', kind: 'full', trigger: 'automatic', status: 'success', started_at: minutesAgo(4), completed_at: minutesAgo(4), created_at: minutesAgo(4) }
}
const demoBackend = {
  GetOverview: async () => demoOverview,
  ListApplications: async () => demoApps,
  TriggerSync: async (_kind: string) => demoOverview.last_attempt as SyncRun,
  GetSyncRun: async (_id: string) => demoOverview.last_attempt as SyncRun,
  GetApplicationEvents: async (releaseID: string, _limit: number) => [
    { id: 2, release_id: releaseID, app_id: releaseID, event_type: 'detection_installed', source: 'detection', created_at: minutesAgo(4) },
    { id: 1, release_id: releaseID, app_id: releaseID, event_type: 'assigned', source: 'server', created_at: minutesAgo(8640) }
  ] satisfies AppEvent[]
}

export const api = {
  overview: (): Promise<Overview> => backend().GetOverview(),
  applications: (): Promise<ManagedApp[]> => backend().ListApplications(),
  triggerSync: (): Promise<SyncRun> => backend().TriggerSync('full'),
  syncRun: (id: string): Promise<SyncRun> => backend().GetSyncRun(id),
  events: (releaseID: string): Promise<AppEvent[]> => backend().GetApplicationEvents(releaseID, 20)
}
