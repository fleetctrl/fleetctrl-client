const dateTimeFormatter = new Intl.DateTimeFormat('en-GB', {
  dateStyle: 'medium',
  timeStyle: 'short',
})

const relativeTimeFormatter = new Intl.RelativeTimeFormat('en', {
  numeric: 'auto',
})

export function formatTime(value?: string) {
  return value ? dateTimeFormatter.format(new Date(value)) : 'Not yet'
}

export function formatRelativeTime(value?: string) {
  if (!value) return 'Not yet'

  const diff = Date.now() - new Date(value).getTime()
  if (diff < 45_000) return 'just now'

  const minutes = Math.round(diff / 60_000)
  if (minutes < 60) return relativeTimeFormatter.format(-minutes, 'minute')

  const hours = Math.round(minutes / 60)
  if (hours < 24) return relativeTimeFormatter.format(-hours, 'hour')

  return relativeTimeFormatter.format(-Math.round(hours / 24), 'day')
}
