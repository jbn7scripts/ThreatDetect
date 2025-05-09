import {
  Component,
  OnInit,
  OnDestroy,
  ViewEncapsulation,
  ViewChild
} from '@angular/core';
import Swal from 'sweetalert2';

import {
  ChartComponent,
  ApexAxisChartSeries,
  ApexChart,
  ApexPlotOptions,
  ApexXAxis,
  ApexDataLabels,
  ApexLegend,
  ApexStroke,
  ApexGrid,
  ApexNonAxisChartSeries,
  ChartType
} from 'ng-apexcharts';

import { DataService } from '../../services/data.service';
import { Router } from '@angular/router';
import { ModelService } from '../../services/model.service';

const DONUT_LABELS = ['Malicious', 'Safe', 'Other'];
const DONUT_COLORS = ['#FF4B4B', '#4ADE80', '#FFB300'];
const LEGEND_TEXT_COLOR = '#fff';

export type DonutChartOptions = {
  series: ApexNonAxisChartSeries;
  chart: ApexChart;
  labels: any;
  colors: any;
  plotOptions: ApexPlotOptions;
  dataLabels: ApexDataLabels;
  legend: ApexLegend;
  tooltip?: any;
};

export type LineChartOptions = {
  series: ApexAxisChartSeries;
  chart: ApexChart;
  xaxis: ApexXAxis;
  stroke: ApexStroke;
  legend: ApexLegend;
  grid: ApexGrid;
  colors?: string[];
};

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css'],
  encapsulation: ViewEncapsulation.None
})
export class DashboardComponent implements OnInit, OnDestroy {
  // Table records
  records: any[] = [];

  // Donut chart
  @ViewChild('donutChart') donutChart?: ChartComponent;
  public donutChartOptions: DonutChartOptions = {
    series: [0, 0, 0],
    chart: { type: 'donut', height: 300 },
    labels: ['Malicious', 'Safe', 'Other'],
    colors: ['#FF4B4B', '#4ADE80', '#FFB300'],
    plotOptions: {},
    dataLabels: { enabled: true },
    legend: {
      show: true,
      position: 'bottom',
      labels: {
        colors: LEGEND_TEXT_COLOR,
        useSeriesColors: false
      }
    },
    tooltip: { enabled: true }
  };

  // Bar chart for top malicious IPs
  public barChartOptions: any = {
    series: [{ name: 'Malicious Events', data: [] }],
    chart: { type: 'bar', height: 250 },
    xaxis: { categories: [] },
    colors: ['#ff5252'],
    dataLabels: { enabled: false },
    plotOptions: { bar: { borderRadius: 6, horizontal: false } },
    legend: { show: false },
    tooltip: { enabled: true }
  };

  // KPIs and other dashboard variables
  totalRecords: number = 0;
  maliciousCount: number = 0;
  safeCount: number = 0;
  detectionAccuracy: number = 0;
  modelVersion: string = '';
  modelLastUpdated: string = '';
  recentAlerts: any[] = [];
  modelStatus = 'Online'; // or fetch from backend if available
  currentModel: string = '';
  selectedModel: string = '';

  private refreshInterval: any;

  constructor(
    private dataService: DataService,
    private router: Router,
    private modelService: ModelService
  ) {}

  ngOnInit(): void {
    this.initializeDashboard();
    this.refreshInterval = setInterval(() => {
      this.fetchOverviewData();
    }, 20000); // 20 seconds
    this.modelService.currentModel$.subscribe(modelName => {
      this.currentModel = modelName;
    });
    // Fetch the current model name from the backend
    this.modelService.getCurrentModel().subscribe((res: any) => {
      if (res && res.current_model) {
        this.currentModel = res.current_model;
      }
    });
  }

  ngOnDestroy(): void {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
    }
  }

  private initializeDashboard() {
    Swal.fire({
      title: 'Loading records...',
      allowOutsideClick: false,
      didOpen: () => Swal.showLoading()
    });
    this.fetchOverviewData();
  }

  private fetchOverviewData() {
    this.dataService.getOverviewRecords().subscribe({
      next: (res: any) => {
        // KPIs
        this.totalRecords = res.kpis.totalRecords;
        this.maliciousCount = res.kpis.maliciousCount;
        this.safeCount = res.kpis.safeCount;
        this.detectionAccuracy = res.kpis.detectionAccuracy;

        // Recent Alerts
        this.recentAlerts = res.recentAlerts;

        // Top Malicious IPs
        this.barChartOptions.series[0].data = res.topMaliciousCounts;
        this.barChartOptions.xaxis.categories = res.topMaliciousIPs;

        // Donut Chart
        this.donutChartOptions = {
          series: [
            res.donutChart.malicious ?? 0,
            res.donutChart.safe ?? 0,
            res.donutChart.other ?? 0
          ],
          chart: { type: 'donut', height: 300 },
          labels: DONUT_LABELS,
          colors: DONUT_COLORS,
          plotOptions: {},
          dataLabels: { enabled: true },
          legend: {
            show: true,
            position: 'bottom',
            labels: {
              colors: LEGEND_TEXT_COLOR,
              useSeriesColors: false
            }
          },
          tooltip: { enabled: true }
        };

        // Table
        this.records = res.records;
        Swal.close();
      },
      error: (err: any) => {
        Swal.fire({
          icon: 'error',
          title: 'Error Fetching Records',
          text: 'Failed to fetch records. Please try again later.'
        });
        console.error('Failed to fetch overview data:', err);
      }
    });
  }

  acknowledgeAlert(alert: any) {
    alert.acknowledged = true;
  }

  openDetails(record: any): void {
    Swal.fire({
      title: `Record #${record.id}`,
      html: `
        <p>Type: ${record.record_type}</p>
        <p>Status: ${record.status}</p>
        <p>Details: ${record.details}</p>
        <p>Created: ${record.created_at}</p>
      `
    });
  }

  formatTimestamp(ts: number): string {
    const d = new Date(ts * 1000); // if ts is seconds-based
    return d.toLocaleString();
  }

  showFeatures(featuresJson: string): void {
    try {
      const featuresObj = JSON.parse(featuresJson);
      const formatted = JSON.stringify(featuresObj, null, 2);
      Swal.fire({
        title: 'Flow Features',
        html: `<pre style="text-align: left; font-size: 0.9rem;">${formatted}</pre>`,
        width: '60vw',
        customClass: { popup: 'text-start' },
        confirmButtonText: 'Close'
      });
    } catch (err) {
      console.error('Error parsing features JSON:', err);
      Swal.fire('Error', 'Could not parse features JSON.', 'error');
    }
  }
}