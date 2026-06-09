import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MonitoringService, SuspiciousIpInfo } from '../../services/monitoring.service';
import { FirewallService } from '../../services/firewall.service';
import { WhitelistService } from '../../services/whitelist.service';
import { AiService, ProposedAction } from '../../services/ai.service';
import { statusClass, sourceLabel } from '../../utils/functions';
import { MESSAGES } from '../../utils/messages';
import { IconComponent } from '../../components/icon/icon';

@Component({
  selector: 'app-firewall',
  standalone: true,
  imports: [CommonModule, FormsModule, IconComponent],
  templateUrl: './firewall.html',
  styleUrl: './firewall.css'
})
export class FirewallComponent implements OnInit {

  suspiciousIps: SuspiciousIpInfo[] = [];
  ipInput  = '';
  chain    = 'ALL';
  message  = '';
  success  = false;

  aiText = '';
  aiActions: ProposedAction[] = [];
  aiLoading = false;
  aiMsg = '';
  aiSuccess = false;
  aiExpanded = new Set<number>();

  readonly statusClass = statusClass;
  readonly sourceLabel = sourceLabel;
  readonly chains = ['ALL', 'INPUT', 'OUTPUT', 'FORWARD'];
  private readonly ipv4OrCidr = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)(\/([0-9]|[1-2][0-9]|3[0-2]))?$/;

  constructor(
    private monitoringService: MonitoringService,
    private firewallService: FirewallService,
    private whitelistService: WhitelistService,
    private aiService: AiService,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit(): void { this.load(); }

  load(): void {
    this.monitoringService.getSuspiciousIps().subscribe(d => {
      this.suspiciousIps = d;
      this.cdr.detectChanges();
    });
  }

  get blockedIps(): SuspiciousIpInfo[] { return this.suspiciousIps.filter(i => i.status === 'BLOCKED'); }
  get warningIps(): SuspiciousIpInfo[] { return this.suspiciousIps.filter(i => i.status === 'WARNING'); }

  private validIp(ip: string): boolean {
    if (!ip) return false;
    if (!this.ipv4OrCidr.test(ip)) {
      this.success = false;
      this.message = `"${ip}" is not a valid IPv4 address or CIDR.`;
      this.cdr.detectChanges();
      return false;
    }
    return true;
  }

  block(): void {
    const ip = this.ipInput.trim();
    if (!this.validIp(ip)) return;
    this.firewallService.blockIp({ ipAddress: ip, chain: this.chain }).subscribe({
      next: res => { this.success = res.success; this.message = res.message; this.ipInput = ''; this.load(); },
      error: err => { this.success = false; this.message = err?.error?.message || MESSAGES.firewall.blockError(ip); this.cdr.detectChanges(); }
    });
  }

  unblock(ip: string): void {
    this.firewallService.unblockIp({ ipAddress: ip, chain: 'ALL' }).subscribe({
      next: res => { this.success = res.success; this.message = res.message; this.load(); },
      error: err => { this.success = false; this.message = err?.error?.message || MESSAGES.firewall.unblockError(ip); this.cdr.detectChanges(); }
    });
  }

  unblockManual(): void {
    const ip = this.ipInput.trim();
    if (!this.validIp(ip)) return;
    this.firewallService.unblockIp({ ipAddress: ip, chain: this.chain }).subscribe({
      next: res => { this.success = res.success; this.message = res.message; this.ipInput = ''; this.load(); },
      error: err => { this.success = false; this.message = err?.error?.message || MESSAGES.firewall.unblockError(ip); this.cdr.detectChanges(); }
    });
  }

  blockFromList(ip: string): void {
    this.firewallService.blockIp({ ipAddress: ip, chain: 'ALL' }).subscribe({
      next: res => { this.success = res.success; this.message = res.message; this.load(); },
      error: err => { this.success = false; this.message = err?.error?.message || MESSAGES.firewall.blockError(ip); this.cdr.detectChanges(); }
    });
  }

  get validCount(): number { return this.aiActions.filter(a => a.valid).length; }

  interpret(): void {
    const text = this.aiText.trim();
    if (!text) return;
    this.aiLoading = true;
    this.aiMsg = '';
    this.aiActions = [];
    this.aiExpanded.clear();
    this.aiService.interpret(text).subscribe({
      next: actions => {
        this.aiActions = actions;
        this.aiLoading = false;
        if (actions.length === 0) { this.aiSuccess = false; this.aiMsg = 'No firewall actions understood from that request.'; }
        this.cdr.detectChanges();
      },
      error: err => {
        this.aiLoading = false;
        this.aiSuccess = false;
        this.aiMsg = err?.error?.message || 'AI request failed.';
        this.cdr.detectChanges();
      }
    });
  }

  applyAll(): void {
    const valid = this.aiActions.filter(a => a.valid);
    if (valid.length === 0) return;
    let done = 0;
    const total = valid.length;
    const finish = () => {
      if (++done >= total) {
        this.aiSuccess = true;
        this.aiMsg = `Applied ${total} action(s).`;
        this.aiActions = [];
        this.aiText = '';
        this.load();
        this.cdr.detectChanges();
      }
    };
    for (const a of valid) {
      if (a.action === 'BLOCK') {
        this.firewallService.blockIp({ ipAddress: a.ipAddress, chain: a.chain || 'ALL' }).subscribe({ next: finish, error: finish });
      } else if (a.action === 'UNBLOCK') {
        this.firewallService.unblockIp({ ipAddress: a.ipAddress, chain: a.chain || 'ALL' }).subscribe({ next: finish, error: finish });
      } else {
        this.whitelistService.addWhitelist({ ipAddress: a.ipAddress, note: a.note || undefined }).subscribe({ next: finish, error: finish });
      }
    }
  }

  clearAi(): void { this.aiActions = []; this.aiMsg = ''; this.aiText = ''; this.aiExpanded.clear(); }

  toggleAction(i: number): void {
    if (this.aiExpanded.has(i)) { this.aiExpanded.delete(i); } else { this.aiExpanded.add(i); }
  }

  effectiveCommand(a: ProposedAction): string {
    if (a.action === 'WHITELIST') {
      return `# application whitelist (no iptables rule)\n# ${a.ipAddress} will be skipped by the auto-blocker`;
    }
    const flag = a.action === 'BLOCK' ? '-A' : '-D';
    const ip = a.ipAddress;
    const chain = a.chain || 'ALL';
    const cmds: string[] = [];
    if (chain === 'ALL' || chain === 'INPUT')  { cmds.push(`sudo iptables ${flag} INPUT -s ${ip} -j DROP`); }
    if (chain === 'ALL' || chain === 'OUTPUT') { cmds.push(`sudo iptables ${flag} OUTPUT -d ${ip} -j DROP`); }
    if (chain === 'ALL' || chain === 'FORWARD') {
      cmds.push(`sudo iptables ${flag} FORWARD -s ${ip} -j DROP`);
      cmds.push(`sudo iptables ${flag} FORWARD -d ${ip} -j DROP`);
    }
    return cmds.join('\n');
  }
}
