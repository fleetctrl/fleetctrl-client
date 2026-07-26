import { useCallback, useMemo, useState } from 'react'

import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { api } from '@/lib/backend'
import type { AppEvent, ManagedApp } from '@/types'

import {
  applicationFilters,
  filterApplications,
  type ApplicationFilter,
} from '../model'
import { ApplicationDetail } from './application-detail'
import { ApplicationsDataTable } from './applications-data-table'

export function ApplicationsPage({ applications }: { applications: ManagedApp[] }) {
  const [filter, setFilter] = useState<ApplicationFilter>('all')
  const [selected, setSelected] = useState<ManagedApp>()
  const [events, setEvents] = useState<AppEvent[]>([])

  const filteredApplications = useMemo(
    () => filterApplications(applications, filter),
    [applications, filter],
  )

  const showDetail = useCallback(async (app: ManagedApp) => {
    setSelected(app)
    setEvents([])
    try {
      setEvents((await api.events(app.release_id)) ?? [])
    } catch {
      setEvents([])
    }
  }, [])

  return (
    <>
      <div className="content">
        <div className="applications-toolbar">
          <p>The requested state is compared with what the client found on this device.</p>
          <Tabs
            value={filter}
            onValueChange={value => setFilter(value as ApplicationFilter)}
            className="max-w-full"
          >
            <TabsList className="h-auto max-w-full justify-start overflow-x-auto">
              {applicationFilters.map(([key, text]) => (
                <TabsTrigger key={key} value={key}>{text}</TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
        </div>
        <ApplicationsDataTable data={filteredApplications} onSelect={showDetail} />
      </div>

      {selected && (
        <ApplicationDetail
          application={selected}
          events={events}
          onClose={() => setSelected(undefined)}
        />
      )}
    </>
  )
}
