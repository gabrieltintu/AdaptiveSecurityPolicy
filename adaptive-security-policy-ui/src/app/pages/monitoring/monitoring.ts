import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SelectModule } from 'primeng/select';
import { MonitoringService, NetworkConnection, FirewallRule } from '../../services/monitoring.service';
import { IconComponent } from '../../components/icon/icon';

@Component({
  selector: 'app-monitoring',
  standalone: true,
  imports: [CommonModule, FormsModule, SelectModule, IconComponent],
  templateUrl: './monitoring.html',
  styleUrl: './monitoring.css'
})
export class MonitoringComponent implements OnInit {

  connections: NetworkConnection[] = [];
  firewallRules: FirewallRule[]    = [];
  loading = true;

  connQuery = '';
  connPage = 0;

  fwQuery = '';
  fwChain = 'ALL';
  fwPage = 0;

  readonly pageSize = 10;

  constructor(
    private monitoringService: MonitoringService,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading = true;
    this.connPage = 0;
    this.fwPage = 0;
    this.monitoringService.getConnections().subscribe(d  => { this.connections   = d; this.cdr.detectChanges(); });
    this.monitoringService.getFirewallRules().subscribe(d => { this.firewallRules = d; this.loading = false; this.cdr.detectChanges(); });
  }

  private matches(query: string, ...fields: (string | undefined | null)[]): boolean {
    const q = query.trim().toLowerCase();
    if (!q) return true;
    return fields.some(f => (f ?? '').toLowerCase().includes(q));
  }

  get filteredConnections(): NetworkConnection[] {
    return this.connections.filter(c => this.matches(this.connQuery, c.protocol, c.state, c.localAddress, c.peerAddress));
  }

  get connTotalPages(): number { return Math.max(1, Math.ceil(this.filteredConnections.length / this.pageSize)); }

  get pagedConnections(): NetworkConnection[] {
    const start = this.connPage * this.pageSize;
    return this.filteredConnections.slice(start, start + this.pageSize);
  }

  onConnSearch(): void { this.connPage = 0; }
  prevConn(): void { if (this.connPage > 0) this.connPage--; }
  nextConn(): void { if (this.connPage < this.connTotalPages - 1) this.connPage++; }

  get chains(): string[] {
    const present = Array.from(new Set(this.firewallRules.map(r => r.chain))).sort();
    return ['ALL', ...present];
  }

  get chainOptions(): { label: string; value: string }[] {
    return this.chains.map(c => ({ label: c === 'ALL' ? 'All chains' : c, value: c }));
  }

  get filteredRules(): FirewallRule[] {
    return this.firewallRules.filter(r =>
      (this.fwChain === 'ALL' || r.chain === this.fwChain)
      && this.matches(this.fwQuery, r.chain, r.target, r.protocol, r.source, r.destination, r.options));
  }

  get fwTotalPages(): number { return Math.max(1, Math.ceil(this.filteredRules.length / this.pageSize)); }

  get pagedRules(): FirewallRule[] {
    const start = this.fwPage * this.pageSize;
    return this.filteredRules.slice(start, start + this.pageSize);
  }

  onFwChange(): void { this.fwPage = 0; }
  prevFw(): void { if (this.fwPage > 0) this.fwPage--; }
  nextFw(): void { if (this.fwPage < this.fwTotalPages - 1) this.fwPage++; }
}
