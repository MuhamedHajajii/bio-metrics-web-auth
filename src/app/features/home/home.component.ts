/**
 * @fileoverview Home page component implementation.
 *
 * This component displays the main landing page for authenticated users.
 */
import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { AuthService } from '../auth/services/auth.service';
import { NavigationService } from '../auth/services/navigation.service';
import { IUser } from '../auth/interfaces/IUser';

/**
 * HomeComponent
 *
 * Main landing page component displayed after successful authentication.
 *
 * @example
 * <app-home></app-home>
 */
@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './home.component.html',
  styleUrl: './home.component.scss'
})
export class HomeComponent {
  private authService = inject(AuthService);
  private navigationService = inject(NavigationService);

  /**
   * Signal to store the current user data.
   * @signal
   */
  protected readonly user = signal<IUser | null>(null);

  /**
   * Signal to indicate if data is being loaded.
   * @signal
   */
  protected readonly isLoading = signal<boolean>(true);

  ngOnInit(): void {
    this.authService.user$.subscribe({
      next: (firebaseUser) => {
        if (firebaseUser) {
          this.user.set({
            email: firebaseUser.email || '',
            username: firebaseUser.displayName || ''
          });
        } else {
          // No user is logged in, redirect to login
          this.navigationService.navigateToLogin();
        }
        this.isLoading.set(false);
      },
      error: (error) => {
        console.error('Error checking authentication:', error);
        this.isLoading.set(false);
      }
    });
  }

  /**
   * Logs the user out and redirects to login page.
   */
  logout(): void {
    this.authService.logout();
    this.navigationService.navigateToLogin();
  }

  /**
   * Navigates to the user profile page.
   */
  goToProfile(): void {
    this.navigationService.navigateToProfile();
  }
}
