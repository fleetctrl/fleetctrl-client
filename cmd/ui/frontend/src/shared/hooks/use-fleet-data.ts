import { useCallback, useEffect, useState } from 'react'

import { api } from '@/lib/backend'
import type { ManagedApp, Overview } from '@/types'

function errorMessage(reason: unknown) {
  return reason instanceof Error ? reason.message : String(reason)
}

export function useFleetData() {
  const [overview, setOverview] = useState<Overview>()
  const [applications, setApplications] = useState<ManagedApp[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)

  const refresh = useCallback(async () => {
    try {
      const nextOverview = await api.overview()
      setOverview(nextOverview)
      setError('')
      setSyncing(Boolean(nextOverview.current_run))

      const nextApplications = await api.applications()
      setApplications(nextApplications ?? [])
    } catch (reason) {
      setError(errorMessage(reason))
      setOverview(undefined)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
    const delay = overview?.current_run ? 1_000 : overview ? 30_000 : 5_000
    const timer = window.setInterval(() => void refresh(), delay)
    return () => window.clearInterval(timer)
  }, [refresh, overview?.current_run?.id, Boolean(overview)])

  const triggerSync = useCallback(async () => {
    setSyncing(true)
    try {
      await api.triggerSync()
      await refresh()
    } catch (reason) {
      setError(errorMessage(reason))
      setSyncing(false)
    }
  }, [refresh])

  return {
    applications,
    error,
    loading,
    overview,
    refresh,
    syncing,
    triggerSync,
  }
}
