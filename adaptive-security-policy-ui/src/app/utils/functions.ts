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

export function actionClass(action: string): string {
  switch (action) {
    case 'BLOCK':
    case 'WHITELIST_REMOVE': return 'status-blocked';
    case 'UNBLOCK':
    case 'WHITELIST_ADD':    return 'badge-green';
    case 'KNOCK':            return 'status-knock';
    case 'CONFIG_CHANGE':    return 'badge-purple';
    default:                 return 'status-warning';
  }
}

export function sourceLabel(source: string): string {
  switch (source) {
    case 'SSH_BRUTEFORCE': return 'SSH brute';
    case 'SSH_PROBE':      return 'SSH probe';
    case 'PORT_SCAN':      return 'Port scan';
    case 'CONN_FLOOD':     return 'Conn flood';
    default:               return source;
  }
}
