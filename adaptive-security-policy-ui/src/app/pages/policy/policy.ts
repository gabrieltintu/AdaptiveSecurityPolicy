import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { PolicyService, SecurityPolicy } from '../../services/policy.service';
import { WhitelistService, WhitelistEntry } from '../../services/whitelist.service';
import { formatDateTime } from '../../utils/functions';
import { IconComponent } from '../../components/icon/icon';

@Component({
  selector: 'app-policy',
  standalone: true,
  imports: [CommonModule, FormsModule, IconComponent],
  templateUrl: './policy.html',
  styleUrl: './policy.css'
})
export class PolicyComponent implements OnInit {

  warningThreshold = 5;
  blockThreshold = 10;
  detectionWindowMinutes = 60;
  autoBlockEnabled = true;
  updatedAt = '';
  updatedBy: string | null = null;

  policyMsg = '';
  policySuccess = false;
  saving = false;

  whitelist: WhitelistEntry[] = [];
  wlIp = '';
  wlNote = '';
  wlMsg = '';
  wlSuccess = false;

  readonly formatDateTime = formatDateTime;
  private readonly ipv4 = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

  constructor(
    private policyService: PolicyService,
    private whitelistService: WhitelistService,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit(): void {
    this.loadPolicy();
    this.loadWhitelist();
  }

  loadPolicy(): void {
    this.policyService.getPolicy().subscribe(p => {
      this.applyPolicy(p);
      this.cdr.detectChanges();
    });
  }

  applyPolicy(p: SecurityPolicy): void {
    this.warningThreshold = p.warningThreshold;
    this.blockThreshold = p.blockThreshold;
    this.detectionWindowMinutes = p.detectionWindowMinutes;
    this.autoBlockEnabled = p.autoBlockEnabled;
    this.updatedAt = p.updatedAt;
    this.updatedBy = p.updatedBy;
  }

  get thresholdInvalid(): boolean {
    return this.warningThreshold >= this.blockThreshold;
  }

  savePolicy(): void {
    this.policyMsg = '';
    if (this.warningThreshold < 1 || this.blockThreshold < 1 || this.detectionWindowMinutes < 1) {
      this.policySuccess = false;
      this.policyMsg = 'All values must be at least 1.';
      return;
    }
    if (this.thresholdInvalid) {
      this.policySuccess = false;
      this.policyMsg = 'Warning threshold must be lower than block threshold.';
      return;
    }
    this.saving = true;
    this.policyService.updatePolicy({
      warningThreshold: this.warningThreshold,
      blockThreshold: this.blockThreshold,
      detectionWindowMinutes: this.detectionWindowMinutes,
      autoBlockEnabled: this.autoBlockEnabled
    }).subscribe({
      next: p => {
        this.applyPolicy(p);
        this.policySuccess = true;
        this.policyMsg = 'Policy updated successfully.';
        this.saving = false;
        this.cdr.detectChanges();
      },
      error: err => {
        this.policySuccess = false;
        this.policyMsg = err?.error?.message || 'Failed to update policy.';
        this.saving = false;
        this.cdr.detectChanges();
      }
    });
  }

  loadWhitelist(): void {
    this.whitelistService.getWhitelist().subscribe(list => {
      this.whitelist = list;
      this.cdr.detectChanges();
    });
  }

  addWhitelist(): void {
    this.wlMsg = '';
    const ip = this.wlIp.trim();
    if (!ip) return;
    if (!this.ipv4.test(ip)) {
      this.wlSuccess = false;
      this.wlMsg = `"${ip}" is not a valid IPv4 address.`;
      return;
    }
    const note = this.wlNote.trim();
    this.whitelistService.addWhitelist({ ipAddress: ip, note: note || undefined }).subscribe({
      next: () => {
        this.wlSuccess = true;
        this.wlMsg = `IP ${ip} added to whitelist.`;
        this.wlIp = '';
        this.wlNote = '';
        this.loadWhitelist();
      },
      error: err => {
        this.wlSuccess = false;
        this.wlMsg = err?.error?.message || `Failed to whitelist ${ip}.`;
        this.cdr.detectChanges();
      }
    });
  }

  removeWhitelist(entry: WhitelistEntry): void {
    this.whitelistService.removeWhitelist(entry.id).subscribe({
      next: () => {
        this.wlSuccess = true;
        this.wlMsg = `IP ${entry.ipAddress} removed from whitelist.`;
        this.loadWhitelist();
      },
      error: () => {
        this.wlSuccess = false;
        this.wlMsg = `Failed to remove ${entry.ipAddress}.`;
        this.cdr.detectChanges();
      }
    });
  }
}
