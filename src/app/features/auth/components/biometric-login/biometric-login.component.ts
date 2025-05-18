/**
 * @fileoverview Component for biometric login
 *
 * Handles user authentication via biometrics (fingerprint/face)
 */
import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { BiometricAuthService } from '../../services/biometric-auth.service';
import { Router } from '@angular/router';
import { finalize } from 'rxjs';

/**
 * BiometricLoginComponent
 *
 * Provides a UI for authenticating with biometrics
 *
 * @example
 * <app-biometric-login></app-biometric-login>
 */
@Component({
  selector: 'app-biometric-login',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="p-4 bg-white rounded-lg shadow-md dark:bg-gray-800">
      <!-- Loading State -->
      @if (isLoading()) {
        <div class="flex flex-col items-center justify-center py-4">
          <div class="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500 mb-4"></div>
          <p class="text-gray-600 dark:text-gray-300">{{ loadingMessage() }}</p>
        </div>
      }

      <!-- Error State -->
      @if (errorMessage() && !isLoading()) {
        <div class="p-3 mb-4 bg-red-100 text-red-700 rounded-md dark:bg-red-900 dark:text-red-100">
          <p class="font-medium">Authentication Failed</p>
          <p>{{ errorMessage() }}</p>
          <button
            (click)="resetState()"
            class="mt-2 px-4 py-2 text-sm bg-white text-red-600 rounded-md hover:bg-red-50 dark:bg-gray-700 dark:hover:bg-gray-600">
            Try Again
          </button>
        </div>
      }

      <!-- Login Prompt (Not authenticated) -->
      @if (!isAuthenticated() && !isLoading() && !errorMessage()) {
        <div class="text-center">
          <h2 class="text-xl font-bold mb-2 text-gray-800 dark:text-white">Biometric Login</h2>
          <p class="mb-4 text-gray-600 dark:text-gray-300">
            Use your {{ biometricType }} to continue
          </p>

          <div class="flex justify-center mb-4">
            @if (biometricType === 'Fingerprint') {
              <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-blue-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04a11.66 11.66 0 0 1-2.255-5.08A7.01 7.01 0 0 1 2 11a8 8 0 1 1 16 0c0 2.862-1.154 7.253-3.302 10.53C13.98 22.478 13.046 23 12 23c-1.532 0-2.94-1.25-3.998-3.055" />
                <circle cx="12" cy="11" r="1" />
                <path d="M6 11a6 6 0 1 1 12 0c0 2.5-.895 6.266-2.742 9.301" />
                <path d="M8.5 11a3.5 3.5 0 1 1 7 0c0 1.191-.335 2.958-1.28 5" />
              </svg>
            } @else {
              <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 text-blue-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="8" r="5" />
                <path d="M20 21v-2a8 8 0 0 0-16 0v2" />
              </svg>
            }
          </div>

          <button
            (click)="login()"
            class="w-full py-3 px-4 bg-blue-500 hover:bg-blue-600 text-white font-medium rounded-md shadow-sm"
            [disabled]="isLoading()">
            Login with {{ biometricType }}
          </button>

          <div class="mt-4">
            <a routerLink="/login" class="text-sm text-blue-500 hover:text-blue-600 dark:text-blue-400">
              Use password instead
            </a>
          </div>
        </div>
      }

      <!-- Success State -->
      @if (isAuthenticated() && !isLoading()) {
        <div class="text-center py-4">
          <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-green-100 text-green-600 mb-4">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-10 w-10" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
            </svg>
          </div>

          <h2 class="text-xl font-bold mb-2 text-gray-800 dark:text-white">Login Successful</h2>
          <p class="mb-4 text-gray-600 dark:text-gray-300">
            You are now signed in!
          </p>

          <button
            (click)="navigateToHome()"
            class="py-2 px-6 bg-blue-500 hover:bg-blue-600 text-white font-medium rounded-md shadow-sm">
            Continue
          </button>
        </div>
      }
    </div>
  `,
  styles: [`
    /* Additional component-specific styles can be added here */
  `]
})
export class BiometricLoginComponent {
  private biometricService = inject(BiometricAuthService);
  private router = inject(Router);

  // State signals
  protected isLoading = signal(false);
  protected errorMessage = signal<string | null>(null);
  protected isAuthenticated = signal(false);
  protected loadingMessage = signal('Waiting for biometric verification...');

  // Default to generic biometric type
  protected biometricType = 'Biometric';

  constructor() {
    this.checkBiometricType();
  }

  /**
   * Checks the current biometric type available on the device
   */
  private async checkBiometricType(): Promise<void> {
    try {
      const capability = await this.biometricService.getBiometricCapability();

      if (capability.isAvailable) {
        switch (capability.type) {
          case 'fingerprint':
            this.biometricType = 'Fingerprint';
            break;
          case 'face':
            this.biometricType = 'Face ID';
            break;
          default:
            this.biometricType = 'Biometric';
        }
      }
    } catch (error) {
      console.error('Error detecting biometric type:', error);
    }
  }

  /**
   * Initiates the biometric login flow
   */
  protected login(): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);
    this.loadingMessage.set('Verifying your identity...');

    // Offer the user biometric login, which will handle both verification and token refresh
    this.biometricService.offerBiometricLogin()
      .pipe(finalize(() => this.isLoading.set(false)))
      .subscribe({
        next: (success) => {
          if (success) {
            this.isAuthenticated.set(true);
            this.errorMessage.set(null);
          } else {
            this.errorMessage.set('Biometric authentication failed. Please try again or use password login.');
          }
        },
        error: (error) => {
          this.errorMessage.set(`Authentication error: ${error.message}`);
          console.error('Biometric auth error:', error);
        }
      });
  }

  /**
   * Navigates to the home page after successful authentication
   */
  protected navigateToHome(): void {
    this.router.navigate(['/dashboard']);
  }

  /**
   * Resets the component state
   */
  protected resetState(): void {
    this.isLoading.set(false);
    this.errorMessage.set(null);
  }
}
