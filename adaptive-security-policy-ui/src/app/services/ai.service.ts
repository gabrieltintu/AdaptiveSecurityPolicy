import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { API_BASE_URL } from '../utils/constants';

export interface ProposedAction {
  action: string;
  ipAddress: string;
  chain: string | null;
  note: string | null;
  valid: boolean;
  error: string | null;
}

@Injectable({ providedIn: 'root' })
export class AiService {

  constructor(private http: HttpClient) {}

  interpret(text: string): Observable<ProposedAction[]> {
    return this.http.post<ProposedAction[]>(`${API_BASE_URL}/ai/firewall/interpret`, { text });
  }
}
