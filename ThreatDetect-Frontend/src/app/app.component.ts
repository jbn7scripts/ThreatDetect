// src/app/app.component.ts
import { Component } from '@angular/core';
import { AuthService } from './services/auth.service';  // ensure correct path
import { Router } from '@angular/router';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  constructor(private authService: AuthService, public router: Router) {}

  isLoggedIn(): boolean {
    return this.authService.isLoggedIn();
  }

  logout() {
    this.authService.logout();
  }

  isActive(route: string): boolean {
    return this.router.url.startsWith(route);
  }
}
