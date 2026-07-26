import { Button } from '@/components/ui/button'
import { Icon } from '@/shared/components/icon'

interface ServiceErrorProps {
  message: string
  onRetry: () => void
}

export function ServiceError({ message, onRetry }: ServiceErrorProps) {
  return (
    <div className="mx-auto mt-4 flex w-[calc(100%-4rem)] max-w-[66rem] items-center gap-3 rounded-md border border-destructive/35 bg-destructive/10 p-2.5 text-destructive max-[760px]:w-[calc(100%-2rem)]">
      <Icon name="warning" className="size-4" />
      <div className="min-w-0 flex-1">
        <strong className="block text-[0.8rem]">FleetCtrl service is unavailable</strong>
        <span className="mt-0.5 block text-[0.7rem]">{message}</span>
      </div>
      <Button variant="destructive" size="sm" onClick={onRetry}>
        Try again
      </Button>
    </div>
  )
}
