import { Component } from '@angular/core';
import { DataService } from '../../services/data.service';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-upload',
  templateUrl: './upload.component.html',
  styleUrls: ['./upload.component.css']
})
export class UploadComponent {
  selectedFile: File | null = null;
  predictions: any[] = [];

  constructor(private dataService: DataService) {}

  onFileSelected(event: any) {
    this.selectedFile = event.target.files[0] ?? null;
  }

  onUpload() {
    if (!this.selectedFile) {
      Swal.fire('Error', 'Please select a CSV or PCAP file first', 'error');
      return;
    }

    this.dataService.uploadFile(this.selectedFile).subscribe({
      next: (res: any) => {
        if (res.predictions) {
          this.predictions = res.predictions;
          Swal.fire('Upload Successful', `Found ${this.predictions.length} predictions`, 'success');
        } else {
          Swal.fire('No Predictions', 'No predictions returned', 'info');
        }
      },
      error: (err) => {
        console.error(err);
        const msg = err.error?.error || 'Upload failed';
        Swal.fire('Error', msg, 'error');
      }
    });
  }
}
