export const MESSAGES = {
  firewall: {
    blockSuccess:   (ip: string) => `IP ${ip} has been blocked successfully.`,
    unblockSuccess: (ip: string) => `IP ${ip} has been unblocked successfully.`,
    blockError:     (ip: string) => `Failed to block IP ${ip}.`,
    unblockError:   (ip: string) => `Failed to unblock IP ${ip}.`,
  },
  alerts: {
    warning: (ip: string, count: number) => `Suspicious IP ${ip} — ${count} failed attempts.`,
    blocked: (ip: string, count: number) => `IP ${ip} automatically blocked after ${count} attempts.`,
  },
  connection: {
    connected:    'Connected to server.',
    disconnected: 'Connection lost. Reconnecting...',
  }
};
