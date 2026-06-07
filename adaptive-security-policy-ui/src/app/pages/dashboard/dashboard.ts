import { Component, OnInit, OnDestroy, ChangeDetectorRef, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import Keycloak from 'keycloak-js';

import { MonitoringService, SuspiciousIpInfo } from '../../services/monitoring.service';
import { FirewallService } from '../../services/firewall.service';
import { WebSocketService, AlertEvent } from '../../services/websocket.service';
import { WS_URL } from '../../utils/constants';
import { formatDateTime, statusClass } from '../../utils/functions';
import { MESSAGES } from '../../utils/messages';
import { IconComponent } from '../../components/icon/icon';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, IconComponent],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.css'
})
export class DashboardComponent implements OnInit, OnDestroy {

  private readonly keycloak = inject(Keycloak);
  readonly isAdmin = this.keycloak.hasRealmRole('ADMIN');

  connectionsCount = 0;
  rulesCount       = 0;
  suspiciousIps: SuspiciousIpInfo[] = [];
  alerts: AlertEvent[]              = [];

  private wsSub?: Subscription;

  readonly formatDateTime = formatDateTime;
  readonly statusClass    = statusClass;

  constructor(
    private monitoringService: MonitoringService,
    private firewallService: FirewallService,
    private webSocketService: WebSocketService,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit(): void {
    this.loadStats();
    this.webSocketService.connect(WS_URL);
    this.wsSub = this.webSocketService.alerts$.subscribe(alert => {
      this.alerts.unshift(alert);
      this.monitoringService.getSuspiciousIps().subscribe(d => {
        this.suspiciousIps = d;
        this.cdr.detectChanges();
      });
    });
  }

  loadStats(): void {
    this.monitoringService.getConnections().subscribe(d  => { this.connectionsCount = d.length; this.cdr.detectChanges(); });
    this.monitoringService.getFirewallRules().subscribe(d => { this.rulesCount = d.length;       this.cdr.detectChanges(); });
    this.monitoringService.getSuspiciousIps().subscribe(d => { this.suspiciousIps = d;           this.cdr.detectChanges(); });
  }

  get blockedCount(): number  { return this.suspiciousIps.filter(i => i.status === 'BLOCKED').length; }
  get warningCount(): number  { return this.suspiciousIps.filter(i => i.status === 'WARNING').length; }

  unblockIp(ip: string): void {
    this.firewallService.unblockIp({ ipAddress: ip, chain: 'ALL' }).subscribe({
      next: () => this.loadStats(),
      error: ()  => {}
    });
  }

  ngOnDestroy(): void {
    this.wsSub?.unsubscribe();
    this.webSocketService.disconnect();
  }
}
