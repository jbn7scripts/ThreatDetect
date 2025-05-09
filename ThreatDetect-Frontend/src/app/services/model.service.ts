// src/app/services/model.service.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from '../environments/environment';
import Swal from 'sweetalert2';
import { BehaviorSubject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class ModelService {
  private currentModelSubject = new BehaviorSubject<string>(''); // default: empty or initial model
  currentModel$ = this.currentModelSubject.asObservable();

  constructor(private http: HttpClient) {}

  listModels() {
    return this.http.get<any>(`${environment.apiUrl}/list_models`);
  }

  getCurrentModel() {
    return this.http.get<any>(`${environment.apiUrl}/current_model`);
  }

  changeModel(modelName: string) {
    return this.http.post<any>(
      `${environment.apiUrl}/change_model`,
      { model_name: modelName }
    );
  }

  showSuccess(modelName: string) {
    Swal.fire('Model switched!', `Current model: ${modelName}`, 'success');
  }

  showError(message: string) {
    Swal.fire('Error', message, 'error');
  }

  setCurrentModel(modelName: string) {
    this.currentModelSubject.next(modelName);
  }
}
