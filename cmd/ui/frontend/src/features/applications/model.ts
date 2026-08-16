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

export function applicationEventLabel(type: string) {
  const labels: Record<string, string> = {
    assigned: 'Application assigned',
    assignment_changed: 'Assignment changed',
    detection_installed: 'Installation detected',
    detection_not_installed: 'Installation not detected',
    install_started: 'Installation started',
    install_succeeded: 'Installation completed',
    install_failed: 'Installation failed',
    uninstall_started: 'Uninstallation started',
    uninstall_succeeded: 'Uninstallation completed',
    uninstall_failed: 'Uninstallation failed',
    upgrade_started: 'Upgrade started',
    upgrade_succeeded: 'Upgrade completed',
    upgrade_failed: 'Upgrade failed',
    update_started: 'Update started',
    update_succeeded: 'Update completed',
    update_failed: 'Update failed',
  }

  return labels[type] || type
}
