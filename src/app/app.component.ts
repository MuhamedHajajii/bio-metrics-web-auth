/**
 * @fileoverview Main application component implementation.
 *
 * This is the root component that bootstraps the entire application.
 */
import { Component, inject, OnInit } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { NavbarComponent } from './core/components/navbar/navbar.component';
import { FooterComponent } from './core/components/footer/footer.component';
import { AuthService } from './features/auth/services/auth.service';

/**
 * AppComponent
 *
 * Root component of the application that hosts the main layout and router outlet.
 *
 * @example
 * <app-root></app-root>
 */
@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, NavbarComponent, FooterComponent],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss'
})
export class AppComponent implements OnInit {
  title = 'authentication-app';
  private authService = inject(AuthService);

  ngOnInit(): void {
    // Check for authentication state on app initialization
    this.authService.user$.subscribe(user => {
      console.log('Current auth state:', user ? 'Authenticated' : 'Not authenticated');
    });
  }
}
