import { Component } from '@angular/core';
import { DataService } from '../../services/data.service';  // or a separate PredictService
import Swal from 'sweetalert2';

@Component({
  selector: 'app-predict',
  templateUrl: './predict.component.html',
  styleUrls: ['./predict.component.css']
})
export class PredictComponent {
  /**
   * We'll store each field in an object. The keys should match
   * the backend's expected JSON keys exactly.
   * But since your old code uses 'duration', 'protocol_type', etc.,
   * you might adapt or rename. This is just an example.
   */
  formData: any = {
    duration: '',
    protocol_type: '',
    service: '',
    flag: '',
    src_bytes: '',
    dst_bytes: '',
    land: '',
    wrong_fragment: '',
    urgent: '',
    hot: '',
    num_failed_logins: '',
    logged_in: '',
    num_compromised: '',
    root_shell: '',
    su_attempted: '',
    num_file_creations: '',
    num_shells: '',
    num_access_files: '',
    num_outbound_cmds: '',
    is_host_login: '',
    is_guest_login: '',
    count: '',
    srv_count: '',
    serror_rate: '',
    rerror_rate: '',
    same_srv_rate: '',
    diff_srv_rate: ''
  };

  predictionResult: string | null = null;

  constructor(private dataService: DataService) {}

  onSubmit() {
    // We'll pass formData to the backend. The backend must map these
    // fields to whatever your model expects.
    this.dataService.predictManual(this.formData).subscribe({
      next: (res: any) => {
        this.predictionResult = res.prediction; // e.g. "BENIGN" or "DOS"
        Swal.fire('Prediction', `Predicted class: ${res.prediction}`, 'success');
      },
      error: (err) => {
        console.error(err);
        Swal.fire('Error', 'Prediction failed', 'error');
      }
    });
  }
}
