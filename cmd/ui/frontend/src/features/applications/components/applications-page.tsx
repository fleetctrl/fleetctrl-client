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
      <div className="mx-auto w-full max-w-[62rem] px-7 pt-6 pb-10 motion-safe:animate-page-enter max-[760px]:px-3 max-[760px]:pt-4 max-[760px]:pb-6">
        <div className="mb-3.5 flex items-center justify-between gap-6 motion-safe:animate-panel-enter max-[760px]:flex-col max-[760px]:items-stretch max-[760px]:gap-3.5">
          <p className="m-0 max-w-96 text-[0.72rem] text-muted-foreground">The requested state is compared with what the client found on this device.</p>
          <Tabs
            value={filter}
            onValueChange={value => setFilter(value as ApplicationFilter)}
            className="max-w-full"
          >
            <TabsList className="h-8 max-w-full justify-start overflow-x-auto rounded-[0.45rem] border border-border/70 bg-muted/65 p-[0.18rem]">
              {applicationFilters.map(([key, text]) => (
                <TabsTrigger className="h-[1.55rem] rounded-[0.3rem] px-2.5 py-0 text-[0.66rem] font-medium" key={key} value={key}>{text}</TabsTrigger>
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
