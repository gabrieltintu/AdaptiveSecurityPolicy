import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { API_BASE_URL } from '../utils/constants';

export interface WhitelistEntry {
  id: number;
  ipAddress: string;
  note: string | null;
  addedBy: string | null;
  createdAt: string;
}

export interface WhitelistAddRequest {
  ipAddress: string;
  note?: string;
}

@Injectable({ providedIn: 'root' })
export class WhitelistService {

  constructor(private http: HttpClient) {}

  getWhitelist(): Observable<WhitelistEntry[]> {
    return this.http.get<WhitelistEntry[]>(`${API_BASE_URL}/whitelist`);
  }

  addWhitelist(request: WhitelistAddRequest): Observable<WhitelistEntry> {
    return this.http.post<WhitelistEntry>(`${API_BASE_URL}/whitelist`, request);
  }

  removeWhitelist(id: number): Observable<void> {
    return this.http.delete<void>(`${API_BASE_URL}/whitelist/${id}`);
  }
}
