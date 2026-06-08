import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { API_BASE_URL } from '../utils/constants';

export interface AnalyticsSummary {
  totalBlocks: number;
  totalWarns: number;
  totalUnblocks: number;
  totalKnocks: number;
  totalConfigChanges: number;
  totalWhitelistChanges: number;
  currentlyBlocked: number;
  currentlyWarning: number;
  uniqueIps: number;
  autoActions: number;
  manualActions: number;
}

export interface ActionCount {
  action: string;
  count: number;
}

export interface DailyCount {
  date: string;
  blocks: number;
  warns: number;
  total: number;
}

export interface IpCount {
  ipAddress: string;
  count: number;
}

export interface AnalyticsOverview {
  summary: AnalyticsSummary;
  actionBreakdown: ActionCount[];
  timeline: DailyCount[];
  topIps: IpCount[];
}

@Injectable({ providedIn: 'root' })
export class AnalyticsService {

  constructor(private http: HttpClient) {}

  getOverview(days = 14): Observable<AnalyticsOverview> {
    const params = new HttpParams().set('days', days);
    return this.http.get<AnalyticsOverview>(`${API_BASE_URL}/analytics/overview`, { params });
  }
}
