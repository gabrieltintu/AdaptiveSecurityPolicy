import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { EventsService, AuditEvent } from '../../services/events.service';
import { formatDateTime, actionClass } from '../../utils/functions';
import { IconComponent } from '../../components/icon/icon';

@Component({
  selector: 'app-history',
  standalone: true,
  imports: [CommonModule, FormsModule, IconComponent],
  templateUrl: './history.html',
  styleUrl: './history.css'
})
export class HistoryComponent implements OnInit {

  events: AuditEvent[] = [];
  totalElements = 0;
  loading = true;

  actionFilter = 'ALL';
  query = '';

  pageSize = 12;
  currentPage = 0;

  readonly actionOrder = ['BLOCK', 'UNBLOCK', 'WARN', 'KNOCK', 'CONFIG_CHANGE', 'WHITELIST_ADD', 'WHITELIST_REMOVE'];
  readonly formatDateTime = formatDateTime;
  readonly actionClass    = actionClass;

  constructor(
    private eventsService: EventsService,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading = true;
    this.eventsService.getEvents(0, 100).subscribe({
      next: page => {
        this.events = page.content;
        this.totalElements = page.totalElements;
        this.currentPage = 0;
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: () => { this.loading = false; this.cdr.detectChanges(); }
    });
  }

  get availableActions(): string[] {
    const present = new Set<string>(this.events.map(e => e.action));
    return this.actionOrder.filter(a => present.has(a));
  }

  get filtered(): AuditEvent[] {
    const q = this.query.trim().toLowerCase();
    return this.events.filter(e => {
      const matchesAction = this.actionFilter === 'ALL' || e.action === this.actionFilter;
      const matchesQuery = !q
        || (e.ipAddress?.toLowerCase().includes(q) ?? false)
        || e.username.toLowerCase().includes(q)
        || (e.details?.toLowerCase().includes(q) ?? false);
      return matchesAction && matchesQuery;
    });
  }

  get totalPages(): number {
    return Math.max(1, Math.ceil(this.filtered.length / this.pageSize));
  }

  get pagedEvents(): AuditEvent[] {
    const start = this.currentPage * this.pageSize;
    return this.filtered.slice(start, start + this.pageSize);
  }

  get blockCount(): number  { return this.events.filter(e => e.action === 'BLOCK').length; }
  get warnCount(): number   { return this.events.filter(e => e.action === 'WARN').length; }
  get manualCount(): number { return this.events.filter(e => e.userType === 'USER').length; }

  setFilter(action: string): void {
    this.actionFilter = action;
    this.currentPage = 0;
  }

  onSearch(): void { this.currentPage = 0; }

  prev(): void { if (this.currentPage > 0) this.currentPage--; }
  next(): void { if (this.currentPage < this.totalPages - 1) this.currentPage++; }
}
