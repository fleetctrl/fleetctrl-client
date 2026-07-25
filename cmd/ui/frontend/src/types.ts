export type SyncStatus = 'queued' | 'running' | 'success' | 'partial' | 'error' | 'interrupted'

export interface SyncRun {
  id: string
  kind: 'device' | 'apps_status' | 'apps_reconcile' | 'full'
  trigger: 'automatic' | 'manual' | 'startup'
  status: SyncStatus
  started_at?: string
  completed_at?: string
  error_message?: string
  created_at: string
}

export interface Overview {
  service_available: boolean
  service_version: string
  server_url: string
  current_run?: SyncRun
  last_attempt?: SyncRun
  last_success?: SyncRun
  last_error?: SyncRun
  checked_at: string
}

export interface ManagedApp {
  release_id: string
  app_id: string
  display_name: string
  publisher?: string
  version?: string
  installer_type: string
  winget_id?: string
  assign_type: string
  desired_action: string
  detected_status: 'unknown' | 'installed' | 'not_installed'
  operation_status: 'idle' | 'installing' | 'uninstalling' | 'upgrading' | 'error'
  first_seen_installed_at?: string
  installed_by_client_at?: string
  last_checked_at?: string
  last_error?: string
}

export interface AppEvent {
  id: number
  release_id: string
  app_id: string
  event_type: string
  source: string
  message?: string
  created_at: string
}

declare global {
  interface Window {
    go?: {
      main?: {
        UIBackend?: {
          GetOverview(): Promise<Overview>
          ListApplications(): Promise<ManagedApp[]>
          TriggerSync(kind: string): Promise<SyncRun>
          GetSyncRun(id: string): Promise<SyncRun>
          GetApplicationEvents(releaseID: string, limit: number): Promise<AppEvent[]>
        }
      }
    }
  }
}
