import { useMemo, useState } from 'react'
import {
  type ColumnDef,
  type SortingState,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table'
import { ArrowUpDown, ChevronRight } from 'lucide-react'

import type { ManagedApp } from '@/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { formatTime } from '@/shared/lib/date'
import { statusText } from '@/shared/lib/status'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

function SortableHeader({
  label,
  onClick,
}: {
  label: string
  onClick: () => void
}) {
  return (
    <Button variant="ghost" size="sm" className="-ml-3 h-8" onClick={onClick}>
      {label}
      <ArrowUpDown className="size-3.5" />
    </Button>
  )
}

export function ApplicationsDataTable({
  data,
  onSelect,
}: {
  data: ManagedApp[]
  onSelect: (app: ManagedApp) => void
}) {
  const [sorting, setSorting] = useState<SortingState>([])
  const columns = useMemo<ColumnDef<ManagedApp>[]>(() => [
    {
      accessorKey: 'display_name',
      header: ({ column }) => (
        <SortableHeader
          label="Application"
          onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')}
        />
      ),
      cell: ({ row }) => {
        const app = row.original
        return (
          <div className="flex min-w-56 items-center">
            <span className="min-w-0">
              <strong className="block truncate font-medium">{app.display_name}</strong>
              <span className="mt-0.5 block truncate text-xs text-muted-foreground">
                {app.publisher || app.installer_type} · {app.version || 'no version'}
              </span>
            </span>
          </div>
        )
      },
    },
    {
      accessorKey: 'desired_action',
      header: ({ column }) => (
        <SortableHeader
          label="Requested action"
          onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')}
        />
      ),
      cell: ({ row }) => (
        <span className="text-muted-foreground">
          {row.original.desired_action === 'install' ? 'Install' : 'Uninstall'}
        </span>
      ),
    },
    {
      accessorKey: 'detected_status',
      header: ({ column }) => (
        <SortableHeader
          label="Device status"
          onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')}
        />
      ),
      cell: ({ row }) => {
        const app = row.original
        return (
          <div className="space-y-1">
            <Badge variant={app.detected_status === 'installed' ? 'secondary' : 'outline'}>
              {statusText[app.detected_status]}
            </Badge>
            {app.operation_status !== 'idle' && (
              <span className="block text-xs text-muted-foreground">
                {statusText[app.operation_status]}
              </span>
            )}
          </div>
        )
      },
    },
    {
      accessorKey: 'last_checked_at',
      header: ({ column }) => (
        <SortableHeader
          label="Last checked"
          onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')}
        />
      ),
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-xs text-muted-foreground">
          {formatTime(row.original.last_checked_at)}
        </span>
      ),
    },
    {
      id: 'actions',
      enableSorting: false,
      cell: ({ row }) => (
        <Button
          variant="ghost"
          size="icon"
          className="size-8"
          aria-label={`View ${row.original.display_name}`}
          onClick={(event) => {
            event.stopPropagation()
            onSelect(row.original)
          }}
        >
          <ChevronRight className="size-4" />
        </Button>
      ),
    },
  ], [onSelect])

  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  })

  return (
    <div className="overflow-hidden rounded-[0.55rem] border border-border/90 bg-card shadow-sm backdrop-blur-lg">
      <Table>
        <TableHeader className="bg-muted/50">
          {table.getHeaderGroups().map(headerGroup => (
            <TableRow key={headerGroup.id}>
              {headerGroup.headers.map(header => (
                <TableHead className="h-10 text-[0.67rem]" key={header.id}>
                  {header.isPlaceholder
                    ? null
                    : flexRender(header.column.columnDef.header, header.getContext())}
                </TableHead>
              ))}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {table.getRowModel().rows.length ? table.getRowModel().rows.map(row => (
            <TableRow
              key={row.id}
              className="h-[3.6rem] cursor-pointer text-[0.72rem] hover:bg-primary/5"
              onClick={() => onSelect(row.original)}
            >
              {row.getVisibleCells().map(cell => (
                <TableCell key={cell.id}>
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </TableCell>
              ))}
            </TableRow>
          )) : (
            <TableRow>
              <TableCell colSpan={columns.length} className="h-32 text-center text-muted-foreground">
                No applications to display.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  )
}
