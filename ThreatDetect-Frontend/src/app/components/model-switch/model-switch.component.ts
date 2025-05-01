import { Component, OnInit } from '@angular/core';
import { ModelService } from '../../services/model.service';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-model-switch',
  templateUrl: './model-switch.component.html',
  styleUrls: ['./model-switch.component.css']
})
export class ModelSwitchComponent implements OnInit {
  availableModels: string[] = [];
  currentModel = '';
  selectedModel = '';

  constructor(private modelService: ModelService) {}

  ngOnInit(): void {
    this.fetchModels();
  }

  fetchModels() {
    // List all .pkl
    this.modelService.listModels().subscribe({
      next: (res) => {
        this.availableModels = res.available_models;
        this.fetchCurrentModel(); // after we get the list
      },
      error: (err) => {
        console.error(err);
        Swal.fire('Error', 'Failed to list models', 'error');
      }
    });
  }

  fetchCurrentModel() {
    this.modelService.getCurrentModel().subscribe({
      next: (res) => {
        if (res.current_model) {
          this.currentModel = res.current_model;
          this.selectedModel = res.current_model; // select it by default
        }
      },
      error: (err) => {
        console.error(err);
      }
    });
  }

  onChangeModel() {
    if (!this.selectedModel) {
      Swal.fire('Error', 'Please select a model', 'error');
      return;
    }

    if (this.selectedModel === this.currentModel) {
      Swal.fire('No Change', 'This model is already the current one', 'info');
      return;
    }

    this.modelService.changeModel(this.selectedModel).subscribe({
      next: (res) => {
        this.currentModel = this.selectedModel;
        Swal.fire('Success', `Model changed to ${this.currentModel}`, 'success');
      },
      error: (err) => {
        console.error(err);
        const msg = err.error?.error || 'Failed to change model';
        Swal.fire('Error', msg, 'error');
      }
    });
  }
}
