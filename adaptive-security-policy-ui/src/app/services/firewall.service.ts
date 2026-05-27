import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { API_BASE_URL } from '../utils/constants';

export interface FirewallActionRequest {
  ipAddress: string;
  chain?: string;
}

export interface FirewallActionResponse {
  success: boolean;
  message: string;
}

@Injectable({ providedIn: 'root' })
export class FirewallService {

  constructor(private http: HttpClient) {}

  blockIp(request: FirewallActionRequest): Observable<FirewallActionResponse> {
    return this.http.post<FirewallActionResponse>(`${API_BASE_URL}/firewall/block`, request);
  }

  unblockIp(request: FirewallActionRequest): Observable<FirewallActionResponse> {
    return this.http.post<FirewallActionResponse>(`${API_BASE_URL}/firewall/unblock`, request);
  }
}
