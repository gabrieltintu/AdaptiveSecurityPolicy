import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { API_BASE_URL } from '../utils/constants';

export type AuditActionType =
  | 'BLOCK'
  | 'UNBLOCK'
  | 'WARN'
  | 'KNOCK'
  | 'CONFIG_CHANGE'
  | 'WHITELIST_ADD'
  | 'WHITELIST_REMOVE';

export interface AuditEvent {
  id: number;
  action: AuditActionType;
  userType: 'USER' | 'SYSTEM';
  username: string;
  ipAddress: string | null;
  details: string | null;
  createdAt: string;
}

export interface Page<T> {
  content: T[];
  totalElements: number;
  totalPages: number;
  number: number;
  size: number;
  first: boolean;
  last: boolean;
  numberOfElements: number;
}

@Injectable({ providedIn: 'root' })
export class EventsService {

  constructor(private http: HttpClient) {}

  getEvents(page = 0, size = 100): Observable<Page<AuditEvent>> {
    const params = new HttpParams().set('page', page).set('size', size);
    return this.http.get<Page<AuditEvent>>(`${API_BASE_URL}/events`, { params });
  }
}
