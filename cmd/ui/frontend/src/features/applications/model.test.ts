import { describe, expect, it } from 'vitest'

import type { ManagedApp } from '@/types'

import { applicationEventLabel, filterApplications, isOutcomeEvent } from './model'

const applications: ManagedApp[] = [
  {
    release_id: 'installed',
    app_id: 'installed',
    display_name: 'Installed app',
    installer_type: 'winget',
    assign_type: 'include',
    desired_action: 'install',
    detected_status: 'installed',
    operation_status: 'idle',
  },
  {
    release_id: 'working',
    app_id: 'working',
    display_name: 'Working app',
    installer_type: 'win32',
    assign_type: 'include',
    desired_action: 'install',
    detected_status: 'not_installed',
    operation_status: 'installing',
  },
  {
    release_id: 'failed',
    app_id: 'failed',
    display_name: 'Failed app',
    installer_type: 'win32',
    assign_type: 'include',
    desired_action: 'install',
    detected_status: 'not_installed',
    operation_status: 'error',
    last_error: 'Installation failed',
  },
]

describe('filterApplications', () => {
  it('filters by detected status', () => {
    expect(filterApplications(applications, 'installed').map(app => app.release_id))
      .toEqual(['installed'])
    expect(filterApplications(applications, 'not_installed').map(app => app.release_id))
      .toEqual(['working', 'failed'])
  })

  it('distinguishes active work from errors', () => {
    expect(filterApplications(applications, 'working').map(app => app.release_id))
      .toEqual(['working'])
    expect(filterApplications(applications, 'error').map(app => app.release_id))
      .toEqual(['failed'])
  })
})

describe('applicationEventLabel', () => {
  it('uses a short outcome label and preserves unknown event types', () => {
    expect(applicationEventLabel('install_succeeded')).toBe('Installed')
    expect(applicationEventLabel('uninstall_succeeded')).toBe('Removed')
    expect(applicationEventLabel('update_succeeded')).toBe('Updated')
    expect(applicationEventLabel('custom_event')).toBe('custom_event')
  })
})

describe('isOutcomeEvent', () => {
  it('keeps only install, removal and update outcomes', () => {
    expect(isOutcomeEvent('install_succeeded')).toBe(true)
    expect(isOutcomeEvent('uninstall_succeeded')).toBe(true)
    expect(isOutcomeEvent('update_succeeded')).toBe(true)
    expect(isOutcomeEvent('install_started')).toBe(false)
    expect(isOutcomeEvent('update_failed')).toBe(false)
    expect(isOutcomeEvent('detection_installed')).toBe(false)
  })
})
