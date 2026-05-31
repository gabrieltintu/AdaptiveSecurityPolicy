/**
 * Formats a date to a readable time string (HH:MM:SS).
 */
export function formatTime(date: Date | string): string {
  return new Date(date).toLocaleTimeString();
}

/**
 * Formats a date to a full readable string (DD/MM/YYYY HH:MM:SS).
 */
export function formatDateTime(date: Date | string): string {
  return new Date(date).toLocaleString();
}

/**
 * Returns the CSS class for a given alert status.
 */
export function statusClass(status: string): string {
  switch (status) {
    case 'BLOCKED': return 'status-blocked';
    case 'KNOCK':   return 'status-knock';
    default:        return 'status-warning';
  }
}
