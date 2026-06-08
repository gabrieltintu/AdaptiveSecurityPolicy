import {
  AfterViewInit,
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  Input,
  OnChanges,
  OnDestroy,
  ViewChild
} from '@angular/core';
import { Chart, ChartData, ChartOptions, ChartType, registerables } from 'chart.js';

Chart.register(...registerables);

@Component({
  selector: 'app-chart',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<canvas #canvas></canvas>`,
  styles: [`:host { display: block; position: relative; width: 100%; height: 100%; }`]
})
export class ChartComponent implements AfterViewInit, OnChanges, OnDestroy {

  @Input() type: ChartType = 'bar';
  @Input() data: ChartData = { labels: [], datasets: [] };
  @Input() options: ChartOptions<any> = {};

  @ViewChild('canvas') private canvasRef!: ElementRef<HTMLCanvasElement>;
  private chart?: Chart;

  ngAfterViewInit(): void {
    this.chart = new Chart(this.canvasRef.nativeElement, {
      type: this.type,
      data: this.data,
      options: this.options
    });
  }

  ngOnChanges(): void {
    if (!this.chart) return;
    this.chart.data = this.data;
    this.chart.options = this.options;
    this.chart.update();
  }

  ngOnDestroy(): void {
    this.chart?.destroy();
  }
}
