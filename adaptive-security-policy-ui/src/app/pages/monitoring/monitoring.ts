import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MonitoringService, NetworkConnection, FirewallRule } from '../../services/monitoring.service';

@Component({
  selector: 'app-monitoring',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './monitoring.html',
  styleUrl: './monitoring.css'
})
export class MonitoringComponent implements OnInit {

  connections: NetworkConnection[] = [];
  firewallRules: FirewallRule[]    = [];
  loading = true;

  constructor(
    private monitoringService: MonitoringService,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading = true;
    this.monitoringService.getConnections().subscribe(d  => { this.connections   = d; this.cdr.detectChanges(); });
    this.monitoringService.getFirewallRules().subscribe(d => { this.firewallRules = d; this.loading = false; this.cdr.detectChanges(); });
  }
}
