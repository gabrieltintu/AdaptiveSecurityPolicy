import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { API_BASE_URL } from '../utils/constants';

export interface NetworkConnection {
  protocol: string;
  state: string;
  localAddress: string;
  peerAddress: string;
}

export interface FirewallRule {
  chain: string;
  packets: string;
  bytes: string;
  target: string;
  protocol: string;
  source: string;
  destination: string;
  options: string;
}

export interface SuspiciousIpInfo {
  ipAddress: string;
  failedAttempts: number;
  status: 'WARNING' | 'BLOCKED';
  detectedAt: string;
}

@Injectable({ providedIn: 'root' })
export class MonitoringService {

  constructor(private http: HttpClient) {}

  getConnections(): Observable<NetworkConnection[]> {
    return this.http.get<NetworkConnection[]>(`${API_BASE_URL}/monitoring/connections`);
  }

  getFirewallRules(): Observable<FirewallRule[]> {
    return this.http.get<FirewallRule[]>(`${API_BASE_URL}/monitoring/firewall-rules`);
  }

  getSuspiciousIps(): Observable<SuspiciousIpInfo[]> {
    return this.http.get<SuspiciousIpInfo[]>(`${API_BASE_URL}/monitoring/suspicious-ips`);
  }
}
