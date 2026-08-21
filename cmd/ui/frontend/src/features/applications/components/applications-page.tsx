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
      <div className="mx-auto w-full max-w-[62rem] px-5 pt-5 pb-10 max-[760px]:px-3 max-[760px]:pt-3 max-[760px]:pb-6">
        <div className="mb-3.5 flex items-center justify-between gap-6 max-[760px]:flex-col max-[760px]:items-stretch max-[760px]:gap-3">
          <p className="m-0 max-w-96 text-xs text-muted-foreground">The requested state is compared with what the client found on this device.</p>
          <Tabs
            value={filter}
            onValueChange={value => setFilter(value as ApplicationFilter)}
            className="max-w-full"
          >
            <TabsList className="max-w-full justify-start overflow-x-auto rounded-sm border border-border bg-muted p-0.5">
              {applicationFilters.map(([key, text]) => (
                <TabsTrigger className="h-6 rounded-[0.15rem] px-2.5 py-0 text-xs font-normal data-[state=active]:font-medium" key={key} value={key}>{text}</TabsTrigger>
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
