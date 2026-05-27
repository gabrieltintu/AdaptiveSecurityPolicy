import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MonitoringService, SuspiciousIpInfo } from '../../services/monitoring.service';
import { FirewallService } from '../../services/firewall.service';
import { statusClass } from '../../utils/functions';
import { MESSAGES } from '../../utils/messages';

@Component({
  selector: 'app-firewall',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './firewall.html',
  styleUrl: './firewall.css'
})
export class FirewallComponent implements OnInit {

  suspiciousIps: SuspiciousIpInfo[] = [];
  ipInput  = '';
  chain    = 'ALL';
  message  = '';
  success  = false;

  readonly statusClass = statusClass;
  readonly chains = ['ALL', 'INPUT', 'OUTPUT', 'FORWARD'];

  constructor(
    private monitoringService: MonitoringService,
    private firewallService: FirewallService
  ) {}

  ngOnInit(): void { this.load(); }

  load(): void {
    this.monitoringService.getSuspiciousIps().subscribe(d => this.suspiciousIps = d);
  }

  get blockedIps(): SuspiciousIpInfo[] { return this.suspiciousIps.filter(i => i.status === 'BLOCKED'); }
  get warningIps(): SuspiciousIpInfo[] { return this.suspiciousIps.filter(i => i.status === 'WARNING'); }

  block(): void {
    if (!this.ipInput.trim()) return;
    this.firewallService.blockIp({ ipAddress: this.ipInput.trim(), chain: this.chain }).subscribe({
      next: res => { this.success = res.success; this.message = res.message; this.ipInput = ''; this.load(); },
      error: ()  => { this.success = false; this.message = MESSAGES.firewall.blockError(this.ipInput); }
    });
  }

  unblock(ip: string): void {
    this.firewallService.unblockIp({ ipAddress: ip, chain: 'ALL' }).subscribe({
      next: res => { this.success = res.success; this.message = res.message; this.load(); },
      error: ()  => { this.success = false; this.message = MESSAGES.firewall.unblockError(ip); }
    });
  }

  blockFromList(ip: string): void {
    this.firewallService.blockIp({ ipAddress: ip, chain: 'ALL' }).subscribe({
      next: res => { this.success = res.success; this.message = res.message; this.load(); },
      error: ()  => { this.success = false; this.message = MESSAGES.firewall.blockError(ip); }
    });
  }
}
