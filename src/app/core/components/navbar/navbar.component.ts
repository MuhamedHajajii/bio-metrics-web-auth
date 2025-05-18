/**
 * @fileoverview Navigation bar component implementation.
 *
 * This component provides the main navigation interface for the application.
 */

import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { AuthService } from '../../../features/auth/services/auth.service';
import { NavigationService } from '../../../features/auth/services/navigation.service';

/**
 * NavbarComponent
 *
 * Main navigation component providing app navigation and user-related controls.
 *
 * @example
 *
 *

.


 * <app-navbar></ 67yuj>
 */
@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './navbar.component.html',
  styleUrl: './navbar.component.scss'
})
export class NavbarComponent {
  private authService = inject(AuthService);
  private navigationService = inject(NavigationService);

  /**
   * Observable of the current authenticated user.
   */
  user$ = this.authService.user$;

  /**
   * Flag to control mobile menu visibility.
   */
  isMobileMenuOpen = false;

  ngOnInit(): void {
    //Called after the constructor, initializing input properties, and the first call to ngOnChanges.
    //Add 'implements OnInit' to the class.
    this.user$.subscribe((user) => {
      console.log(user);
    });
  }

  /**
   * Toggles the mobile menu open/closed state.
   */
  toggleMobileMenu(): void {
    this.isMobileMenuOpen = !this.isMobileMenuOpen;
  }

  /**
   * Logs the user out and navigates to the login page.
   */
  logout(): void {
    this.authService.logout();
    this.navigationService.navigateToLogin();
  }
}
