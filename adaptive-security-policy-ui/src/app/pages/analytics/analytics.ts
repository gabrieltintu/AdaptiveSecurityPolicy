import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ChartData, ChartOptions } from 'chart.js';
import { AnalyticsService, AnalyticsOverview } from '../../services/analytics.service';
import { IconComponent } from '../../components/icon/icon';
import { ChartComponent } from '../../components/chart/chart';

@Component({
  selector: 'app-analytics',
  standalone: true,
  imports: [CommonModule, IconComponent, ChartComponent],
  templateUrl: './analytics.html',
  styleUrl: './analytics.css'
})
export class AnalyticsComponent implements OnInit {

  loading = true;
  failed = false;
  days = 14;
  overview?: AnalyticsOverview;

  timelineData: ChartData = { labels: [], datasets: [] };
  timelineOptions: ChartOptions = {};
  actionData: ChartData = { labels: [], datasets: [] };
  actionOptions: ChartOptions<'doughnut'> = {};
  actorData: ChartData = { labels: [], datasets: [] };
  actorOptions: ChartOptions<'doughnut'> = {};
  topIpsData: ChartData = { labels: [], datasets: [] };
  topIpsOptions: ChartOptions = {};

  private readonly actionColors: Record<string, string> = {
    BLOCK: '#f87171',
    WARN: '#fbbf24',
    UNBLOCK: '#34d399',
    KNOCK: '#22d3ee',
    CONFIG_CHANGE: '#a855f7',
    WHITELIST_ADD: '#3b82f6',
    WHITELIST_REMOVE: '#ec4899'
  };

  constructor(
    private analyticsService: AnalyticsService,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.loading = true;
    this.failed = false;
    this.analyticsService.getOverview(this.days).subscribe({
      next: data => {
        this.overview = data;
        this.buildCharts(data);
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.failed = true;
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  setRange(days: number): void {
    if (this.days === days) return;
    this.days = days;
    this.load();
  }

  private buildCharts(d: AnalyticsOverview): void {
    const text = this.cssVar('--text-secondary');
    const grid = 'rgba(255,255,255,0.06)';

    this.timelineData = {
      labels: d.timeline.map(t => this.dayLabel(t.date)),
      datasets: [
        {
          label: 'Blocks',
          data: d.timeline.map(t => t.blocks),
          borderColor: this.actionColors['BLOCK'],
          backgroundColor: 'rgba(248,113,113,0.16)',
          fill: true,
          tension: 0.35,
          pointRadius: 2,
          borderWidth: 2
        },
        {
          label: 'Warnings',
          data: d.timeline.map(t => t.warns),
          borderColor: this.actionColors['WARN'],
          backgroundColor: 'rgba(251,191,36,0.12)',
          fill: true,
          tension: 0.35,
          pointRadius: 2,
          borderWidth: 2
        }
      ]
    };
    this.timelineOptions = this.axisOptions(text, grid, true);

    this.actionData = {
      labels: d.actionBreakdown.map(a => this.prettyAction(a.action)),
      datasets: [{
        data: d.actionBreakdown.map(a => a.count),
        backgroundColor: d.actionBreakdown.map(a => this.actionColors[a.action] ?? '#a855f7'),
        borderColor: 'rgba(7,0,15,0.55)',
        borderWidth: 2
      }]
    };
    this.actionOptions = this.donutOptions(text);

    this.actorData = {
      labels: ['Automatic', 'Manual'],
      datasets: [{
        data: [d.summary.autoActions, d.summary.manualActions],
        backgroundColor: ['#3b82f6', '#a855f7'],
        borderColor: 'rgba(7,0,15,0.55)',
        borderWidth: 2
      }]
    };
    this.actorOptions = this.donutOptions(text);

    this.topIpsData = {
      labels: d.topIps.map(i => i.ipAddress),
      datasets: [{
        label: 'Threat events',
        data: d.topIps.map(i => i.count),
        backgroundColor: 'rgba(168,85,247,0.5)',
        borderColor: '#a855f7',
        borderWidth: 1,
        borderRadius: 4
      }]
    };
    this.topIpsOptions = {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, ticks: { color: text, precision: 0, font: { size: 11 } }, grid: { color: grid } },
        y: { ticks: { color: text, font: { size: 11 } }, grid: { display: false } }
      }
    };
  }

  private axisOptions(text: string, grid: string, legend: boolean): ChartOptions {
    return {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: legend, labels: { color: text, usePointStyle: true, boxWidth: 8, font: { size: 11 } } }
      },
      scales: {
        x: { ticks: { color: text, font: { size: 11 } }, grid: { color: grid } },
        y: { beginAtZero: true, ticks: { color: text, precision: 0, font: { size: 11 } }, grid: { color: grid } }
      }
    };
  }

  private donutOptions(text: string): ChartOptions<'doughnut'> {
    return {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '62%',
      plugins: {
        legend: { position: 'bottom', labels: { color: text, usePointStyle: true, boxWidth: 8, padding: 12, font: { size: 11 } } }
      }
    };
  }

  private cssVar(name: string): string {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || '#9ca3af';
  }

  private dayLabel(iso: string): string {
    return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }

  private prettyAction(action: string): string {
    return action.charAt(0) + action.slice(1).toLowerCase().replace(/_/g, ' ');
  }
}
