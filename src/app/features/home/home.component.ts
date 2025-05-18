/**
 * @fileoverview Home page component implementation.
 *
 * This component displays the main landing page for authenticated users.
 */
import { Component, inject, signal, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { AuthService } from '../auth/services/auth.service';
import { NavigationService } from '../auth/services/navigation.service';
import { BiometricAuthService } from '../auth/services/biometric-auth.service';
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
export class HomeComponent implements OnInit {
  private authService = inject(AuthService);
  private navigationService = inject(NavigationService);
  private biometricAuthService = inject(BiometricAuthService);

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

  /**
   * Signal to indicate if the user was authenticated via biometrics.
   * @signal
   */
  protected readonly isBiometricAuth = signal<boolean>(false);

  /**
   * Initializes the component and loads user data.
   */
  ngOnInit(): void {
    console.log('Home component initialized');

    // Check for biometric authentication first
    const hasBiometricToken = this.biometricAuthService.hasBiometricToken();
    this.isBiometricAuth.set(hasBiometricToken);
    console.log('User authenticated via biometrics:', hasBiometricToken);

    // Subscribe to the authenticated user from either source
    this.authService.authenticatedUser$.subscribe({
      next: (userData) => {
        console.log('Received user data:', userData);
        if (userData) {
          this.user.set(userData);
          this.isLoading.set(false);
        } else {
          // Fall back to Firebase auth
          this.authService.user$.subscribe({
            next: (firebaseUser) => {
              console.log('Received Firebase user:', firebaseUser);
              if (firebaseUser) {
                this.user.set({
                  email: firebaseUser.email || '',
                  username: firebaseUser.displayName || ''
                });
                this.isLoading.set(false);
              } else {
                // No user is logged in, redirect to login
                console.log('No authenticated user found, redirecting to login');
                this.navigationService.navigateToLogin();
              }
            },
            error: (error) => {
              console.error('Error checking authentication:', error);
              this.isLoading.set(false);
              this.navigationService.navigateToLogin();
            }
          });
        }
      }
    });
  }

  /**
   * Logs the user out and redirects to login page.
   * Also clears any biometric authentication tokens.
   */
  logout(): void {
    // Clear biometric token if it exists
    if (this.isBiometricAuth()) {
      this.biometricAuthService.clearBiometricToken();
    }

    // Logout from Firebase
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
