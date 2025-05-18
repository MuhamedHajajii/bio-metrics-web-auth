/**
 * @fileoverview Authentication navigation service implementation.
 *
 * Handles navigation between authentication-related pages.
 */

import { inject, Injectable } from '@angular/core';
import { Router } from '@angular/router';

/**
 * NavigationService
 *
 * Provides navigation functionality for authentication flows,
 * ensuring consistent routing throughout the auth feature.
 */
@Injectable({
  providedIn: 'root'
})
export class NavigationService {
  private router = inject(Router);

  /**
   * Navigates to the login page.
   */
  navigateToLogin(): void {
    this.router.navigate(['/auth/login']);
  }

  /**
   * Navigates to the register page.
   */
  navigateToRegister(): void {
    this.router.navigate(['/auth/register']);
  }

  /**
   * Navigates to the password reset page.
   */
  navigateToResetPassword(): void {
    this.router.navigate(['/auth/reset-password']);
  }

  /**
   * Navigates to the user profile page.
   */
  navigateToProfile(): void {
    this.router.navigate(['/auth/profile']);
  }

  /**
   * Navigates to the home page.
   */
  navigateToHome(): void {
    this.router.navigate(['/home']);
  }
}
