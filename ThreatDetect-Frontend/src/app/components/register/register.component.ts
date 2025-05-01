// src/app/pages/register/register.component.ts
import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import Swal from "sweetalert2";

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['../login/login.component.css']
})
export class RegisterComponent {
  name = '';
  email = '';
  password = '';

  constructor(private authService: AuthService, private router: Router) {}

  onSubmit() {
    // loading animation
    Swal.fire({
      title: 'Loading...',
      allowOutsideClick: false,
      didOpen: () => {
        Swal.showLoading();
      }
    });
    this.authService.register(this.name, this.email, this.password).subscribe({
      next: (res: any) => {
        this.authService.handleRegisterSuccess();

        this.router.navigate(['/login'])

      },
      error: (err) => {
        console.error(err);
      }
    });
  }
}
