// src/app/services/auth.service.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from '../environments/environment';
import Swal from 'sweetalert2';
import {Router} from "@angular/router";

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  constructor(private http: HttpClient, private router: Router) {}

  login(email: string, password: string) {
    return this.http.post(`${environment.apiUrl}/login`, { email, password });
  }

  register(name: string, email: string, password: string) {
    return this.http.post(`${environment.apiUrl}/register`, { name, email, password });
  }

  handleLoginSuccess(token: string) {
    localStorage.setItem('token', token);
    Swal.fire('Login Successful', '', 'success');
  }

  handleRegisterSuccess() {
    Swal.fire('Registration Successful', '', 'success');
  }

  isLoggedIn(): boolean {
    return !!localStorage.getItem('token');
  }

  logout() {
    localStorage.removeItem('token');
    this.router.navigate(['/home']);
    Swal.fire('Logged Out', '', 'info');
  }
}
