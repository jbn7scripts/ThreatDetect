import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from '../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class DataService {
  constructor(private http: HttpClient) {}

  getSniffedData() {
    return this.http.get<any>(`${environment.apiUrl}/sniffed_data`);
  }

  getLabelCounts() {
    return this.http.get<any>(`${environment.apiUrl}/chart_data`);
  }

  predictManual(features: any) {
    return this.http.post<any>(`${environment.apiUrl}/predict`, features);
  }

  // For batch upload:
  uploadFile(file: File) {
    const formData = new FormData();
    formData.append('file', file);
    return this.http.post<any>(`${environment.apiUrl}/upload`, formData);
  }

  getOverviewRecords() {
    const token = localStorage.getItem('token');
    const headers = { Authorization: `Bearer ${token}` };
    return this.http.get<any>(`${environment.apiUrl}/overview_records`, { headers });
  }
}
