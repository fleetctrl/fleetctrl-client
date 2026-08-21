import type { ManagedApp } from '@/types'

export type ApplicationFilter = 'all' | 'installed' | 'not_installed' | 'error' | 'working'

export const applicationFilters: [ApplicationFilter, string][] = [
  ['all', 'All'],
  ['installed', 'Installed'],
  ['not_installed', 'Not installed'],
  ['error', 'Error'],
  ['working', 'In progress'],
]

export function filterApplications(applications: ManagedApp[], filter: ApplicationFilter) {
  return applications.filter(app => {
    if (filter === 'all') return true
    if (filter === 'error') return app.operation_status === 'error' || Boolean(app.last_error)
    if (filter === 'working') return !['idle', 'error'].includes(app.operation_status)
    return app.detected_status === filter
  })
}

const outcomeEventLabels: Record<string, string> = {
  install_succeeded: 'Installed',
  uninstall_succeeded: 'Removed',
  update_succeeded: 'Updated',
}

export function isOutcomeEvent(type: string) {
  return type in outcomeEventLabels
}

export function applicationEventLabel(type: string) {
  return outcomeEventLabels[type] || type
}
