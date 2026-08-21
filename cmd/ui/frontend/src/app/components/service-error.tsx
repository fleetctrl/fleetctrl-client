import { Button } from '@/components/ui/button'
import { Icon } from '@/shared/components/icon'

interface ServiceErrorProps {
  message: string
  onRetry: () => void
}

export function ServiceError({ message, onRetry }: ServiceErrorProps) {
  return (
    <div className="mx-auto mt-3 flex w-[calc(100%-2.5rem)] max-w-[62rem] items-center gap-3 rounded-md border border-destructive/40 p-2.5 text-xs text-destructive max-[760px]:w-[calc(100%-1.5rem)]">
      <Icon name="warning" className="size-4 shrink-0" />
      <div className="min-w-0 flex-1">
        <strong className="block">FleetCtrl service is unavailable</strong>
        <span className="mt-0.5 block opacity-80">{message}</span>
      </div>
      <Button variant="destructive" size="sm" onClick={onRetry}>
        Try again
      </Button>
    </div>
  )
}
