import { Button } from '@/components/ui/button'
import { Icon } from '@/shared/components/icon'

interface ServiceErrorProps {
  message: string
  onRetry: () => void
}

export function ServiceError({ message, onRetry }: ServiceErrorProps) {
  return (
    <div className="alert">
      <Icon name="warning" />
      <div>
        <strong>FleetCtrl service is unavailable</strong>
        <span>{message}</span>
      </div>
      <Button variant="destructive" size="sm" onClick={onRetry}>
        Try again
      </Button>
    </div>
  )
}
