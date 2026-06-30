import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { API_BASE_URL } from '../utils/constants';

export interface SecurityPolicy {
  warningThreshold: number;
  blockThreshold: number;
  detectionWindowMinutes: number;
  autoBlockEnabled: boolean;
  sshBruteforceEnabled: boolean;
  sshProbeEnabled: boolean;
  portScanEnabled: boolean;
  connFloodEnabled: boolean;
  portKnockingEnabled: boolean;
  portScanMinPorts: number;
  connFloodMinConnections: number;
  updatedAt: string;
  updatedBy: string | null;
}

export interface PolicyUpdateRequest {
  warningThreshold: number;
  blockThreshold: number;
  detectionWindowMinutes: number;
  autoBlockEnabled: boolean;
  sshBruteforceEnabled: boolean;
  sshProbeEnabled: boolean;
  portScanEnabled: boolean;
  connFloodEnabled: boolean;
  portScanMinPorts: number;
  connFloodMinConnections: number;
}

@Injectable({ providedIn: 'root' })
export class PolicyService {

  constructor(private http: HttpClient) {}

  getPolicy(): Observable<SecurityPolicy> {
    return this.http.get<SecurityPolicy>(`${API_BASE_URL}/policy`);
  }

  updatePolicy(request: PolicyUpdateRequest): Observable<SecurityPolicy> {
    return this.http.put<SecurityPolicy>(`${API_BASE_URL}/policy`, request);
  }

  setPortKnocking(enabled: boolean): Observable<SecurityPolicy> {
    return this.http.post<SecurityPolicy>(`${API_BASE_URL}/policy/port-knocking`, { enabled });
  }
}
