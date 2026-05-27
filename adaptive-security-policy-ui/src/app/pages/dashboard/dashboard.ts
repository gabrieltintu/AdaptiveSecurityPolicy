import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';

import { MonitoringService, NetworkConnection, FirewallRule, SuspiciousIpInfo } from '../../services/monitoring.service';
import { FirewallService } from '../../services/firewall.service';
import { WebSocketService, AlertEvent } from '../../services/websocket.service';
import { WS_URL } from '../../utils/constants';
import { formatDateTime, statusClass } from '../../utils/functions';
import { MESSAGES } from '../../utils/messages';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.css'
})
export class DashboardComponent implements OnInit, OnDestroy {

  connections: NetworkConnection[]   = [];
  firewallRules: FirewallRule[]      = [];
  suspiciousIps: SuspiciousIpInfo[]  = [];
  alerts: AlertEvent[]               = [];

  blockIpInput = '';
  actionMessage = '';
  actionSuccess = false;

  private wsSub?: Subscription;

  readonly formatDateTime = formatDateTime;
  readonly statusClass    = statusClass;

  constructor(
    private monitoringService: MonitoringService,
    private firewallService: FirewallService,
    private webSocketService: WebSocketService
  ) {}

  ngOnInit(): void {
    this.loadAll();
    this.webSocketService.connect(WS_URL);
    this.wsSub = this.webSocketService.alerts$.subscribe(alert => {
      this.alerts.unshift(alert);
      this.monitoringService.getSuspiciousIps().subscribe(d => this.suspiciousIps = d);
    });
  }

  loadAll(): void {
    this.monitoringService.getConnections().subscribe(d  => this.connections   = d);
    this.monitoringService.getFirewallRules().subscribe(d => this.firewallRules = d);
    this.monitoringService.getSuspiciousIps().subscribe(d => this.suspiciousIps = d);
  }

  get blockedCount(): number {
    return this.suspiciousIps.filter(ip => ip.status === 'BLOCKED').length;
  }

  get warningCount(): number {
    return this.suspiciousIps.filter(ip => ip.status === 'WARNING').length;
  }

  blockIp(ip: string): void {
    this.firewallService.blockIp({ ipAddress: ip, chain: 'ALL' }).subscribe({
      next: res => { this.actionSuccess = res.success; this.actionMessage = res.message; this.loadAll(); },
      error: ()  => { this.actionSuccess = false; this.actionMessage = MESSAGES.firewall.blockError(ip); }
    });
  }

  unblockIp(ip: string): void {
    this.firewallService.unblockIp({ ipAddress: ip, chain: 'ALL' }).subscribe({
      next: res => { this.actionSuccess = res.success; this.actionMessage = res.message; this.loadAll(); },
      error: ()  => { this.actionSuccess = false; this.actionMessage = MESSAGES.firewall.unblockError(ip); }
    });
  }

  submitBlock(): void {
    if (this.blockIpInput.trim()) {
      this.blockIp(this.blockIpInput.trim());
      this.blockIpInput = '';
    }
  }

  ngOnDestroy(): void {
    this.wsSub?.unsubscribe();
    this.webSocketService.disconnect();
  }
}
