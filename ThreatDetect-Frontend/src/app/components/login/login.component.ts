// src/app/pages/login/login.component.ts
import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent {
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
    this.authService.login(this.email, this.password).subscribe({
      next: (res: any) => {
        if (res.token) {
          this.authService.handleLoginSuccess(res.token);
          this.router.navigate(['/dashboard']);
        }
      },
      error: (err) => {
        console.log(err);
      }
    });
  }
}
