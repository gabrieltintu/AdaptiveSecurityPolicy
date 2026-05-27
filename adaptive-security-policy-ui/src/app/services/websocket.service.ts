import { Injectable, OnDestroy } from '@angular/core';
import { Subject } from 'rxjs';

export interface AlertEvent {
  ipAddress: string;
  failedAttempts: number;
  status: 'WARNING' | 'BLOCKED';
  message: string;
  timestamp: string;
}

declare var SockJS: any;
declare var Stomp: any;

@Injectable({ providedIn: 'root' })
export class WebSocketService implements OnDestroy {

  private stompClient: any;
  private alertsSubject = new Subject<AlertEvent>();

  alerts$ = this.alertsSubject.asObservable();

  connect(wsUrl: string): void {
    const socket = new SockJS(wsUrl);
    this.stompClient = Stomp.over(socket);
    this.stompClient.debug = null;

    this.stompClient.connect({}, () => {
      this.stompClient.subscribe('/topic/alerts', (message: any) => {
        const event: AlertEvent = JSON.parse(message.body);
        this.alertsSubject.next(event);
      });
    });
  }

  disconnect(): void {
    if (this.stompClient?.connected) {
      this.stompClient.disconnect();
    }
  }

  ngOnDestroy(): void {
    this.disconnect();
  }
}
