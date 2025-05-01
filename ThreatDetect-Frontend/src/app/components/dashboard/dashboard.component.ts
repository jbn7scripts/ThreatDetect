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
  ApexNonAxisChartSeries
} from 'ng-apexcharts';

import { DataService } from '../../services/data.service';
import { Router } from '@angular/router';

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

// interface RecordData {
//   id?: number;
//   record_type?: string;    // or recordType if you prefer
//   status?: string;
//   details?: string;
//   created_at?: string;
//   displayId?: string; // optional
// }

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css'],
  encapsulation: ViewEncapsulation.None
})
export class DashboardComponent implements OnInit, OnDestroy {
  // We store table records
  records: any = [];

  // Donut chart
  @ViewChild('donutChart') donutChart?: ChartComponent;
  public donutChartOptions: Partial<DonutChartOptions> | any;

  // Line chart
  @ViewChild('lineChart') lineChart?: ChartComponent;
  public lineChartOptions: Partial<LineChartOptions> | any;

  private refreshInterval: any;

  constructor(
    private dataService: DataService,
    private router: Router
  ) {}

  ngOnInit(): void {
    // fetch data upon init
    this.initializeDashboard();

    // auto-refresh every 30s (optional)
    this.refreshInterval = setInterval(() => {
      this.fetchOverviewData();
    }, 20_000);
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
    // This will return { records, donutChart, lineChart }
    this.dataService.getOverviewRecords().subscribe({
      next: (res: any) => {

        // 1) Populate table
        this.records = res.records || [];
        console.log(this.records);


        // 2) Donut chart
        this.donutChartOptions = {
          series: [
            res.donutChart?.malicious || 0,
            res.donutChart?.safe || 0,
            res.donutChart?.other || 0
          ],
          chart: {
            type: 'donut',
            height: 300
          },
          labels: ['Malicious', 'Safe', 'Other'],
          colors: ['#E91E63', '#546E7A', '#FF9800'],
          plotOptions: {
            pie: {
              donut: {
                size: '75%',
                labels: {
                  show: true,
                  total: {
                    show: true,
                    label: 'Total',
                    formatter: (w: any) => {
                      return w.globals.seriesTotals.reduce((a: any, b: any) => a + b, 0);
                    }
                  }
                }
              }
            }
          },
          dataLabels: {
            enabled: true
          },
          legend: {
            show: true,
            position: 'bottom'
          },
          tooltip: {
            enabled: true
          }
        };

        // 3) Line chart
        const lineData = res.lineChart || [];
        const categories = lineData.map((item: any) => item.date);
        const safeData = lineData.map((item: any) => item.safe);
        const maliciousData = lineData.map((item: any) => item.malicious);
        const otherData = lineData.map((item: any) => item.other);

        this.lineChartOptions = {
          series: [
            { name: 'Safe', data: safeData, color: '#546E7A' },
            { name: 'Malicious', data: maliciousData, color: '#E91E63' },
            { name: 'Other', data: otherData, color: '#FF9800' }
          ],
          chart: {
            type: 'line',
            height: 260,
            toolbar: {
              show: true
            }
          },
          xaxis: {
            categories: categories,
            labels: {
              rotate: -50,
              rotateAlways: true
            }
          },
          stroke: {
            width: 3,
            curve: 'smooth'
          },
          legend: {
            position: 'top'
          },
          grid: {
            borderColor: '#f1f1f1'
          }
        };

        Swal.close();
      },
      error: (err) => {
        Swal.fire({
          icon: 'error',
          title: 'Error Fetching Records',
          text: 'Failed to fetch records. Please try again later.'
        });
        console.error('Failed to fetch overview data:', err);
      }
    });
  }

  openDetails(record: any): void {
    // Show a sweetalert with record details
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
    // Convert Unix epoch float to local date/time
    const d = new Date(ts * 1000);  // if ts is seconds-based
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
        customClass: {
          popup: 'text-start'
        },
        confirmButtonText: 'Close'
      });
    } catch (err) {
      console.error('Error parsing features JSON:', err);
      Swal.fire('Error', 'Could not parse features JSON.', 'error');
    }
  }
}
