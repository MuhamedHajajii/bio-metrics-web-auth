/**
 * @fileoverview Component for setting up biometric authentication
 *
 * Allows users to enable or disable biometric login options
 */
import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { BiometricAuthService } from '../../services/biometric-auth.service';
import { finalize } from 'rxjs';

/**
 * BiometricSetupComponent
 *
 * Provides UI for enabling/disabling biometric authentication
 * and displays device capability information
 *
 * @example
 * <app-biometric-setup></app-biometric-setup>
 */
@Component({
  selector: 'app-biometric-setup',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="p-4 bg-white rounded-lg shadow-md dark:bg-gray-800">
      <h2 class="text-xl font-bold mb-4 text-gray-800 dark:text-white">Biometric Authentication</h2>

      <!-- Loading State -->
      @if (isLoading()) {
        <div class="flex justify-center items-center py-4">
          <div class="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500"></div>
        </div>
      }

      <!-- Error State -->
      @if (errorMessage()) {
        <div class="p-3 mb-4 bg-red-100 text-red-700 rounded-md dark:bg-red-900 dark:text-red-100">
          {{ errorMessage() }}
        </div>
      }

      <!-- Capability Information -->
      @if (biometricCapability() && !isLoading()) {
        <div class="mb-4">
          @if (biometricCapability()?.isAvailable) {
            <div class="p-3 bg-green-100 text-green-700 rounded-md dark:bg-green-900 dark:text-green-100">
              <p class="font-medium">Your device supports biometric authentication!</p>
              <p>Type: {{ getBiometricTypeLabel(biometricCapability()?.type || null) }}</p>
            </div>
          } @else {
            <div class="p-3 bg-yellow-100 text-yellow-700 rounded-md dark:bg-yellow-900 dark:text-yellow-100">
              <p>Your device does not support biometric authentication.</p>
            </div>
          }
        </div>
      }

      <!-- Setup Actions -->
      @if (biometricCapability()?.isAvailable && !isSetupComplete()) {
        <button
          (click)="setupBiometric()"
          [disabled]="isLoading()"
          class="w-full py-2 px-4 bg-blue-500 hover:bg-blue-600 text-white font-medium rounded-md shadow-sm disabled:opacity-50 disabled:cursor-not-allowed">
          Set Up {{ getBiometricTypeLabel(biometricCapability()?.type || null) }} Login
        </button>
      }

      <!-- Toggle Biometric (if already set up) -->
      @if (isBiometricRegistered()) {
        <div class="flex items-center justify-between py-3">
          <span class="text-gray-700 dark:text-gray-300">Use biometric login</span>
          <label class="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              [checked]="isBiometricEnabled()"
              (change)="toggleBiometric($event)"
              class="sr-only peer">
            <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
          </label>
        </div>
      }

      <!-- Setup Complete Feedback -->
      @if (isSetupComplete()) {
        <div class="mt-4 p-3 bg-green-100 text-green-700 rounded-md dark:bg-green-900 dark:text-green-100">
          <p>Biometric login has been set up successfully!</p>
          <p class="text-sm mt-1">You can now use your biometric authentication to log in.</p>
        </div>
      }

      <!-- Debug/Testing Section (in development mode) -->
      @if (showDebugOptions()) {
        <div class="mt-6 pt-4 border-t border-gray-200 dark:border-gray-700">
          <h3 class="text-lg font-medium mb-2 text-gray-800 dark:text-white">Testing Options</h3>
          <button
            (click)="toggleMockMode()"
            class="py-2 px-4 bg-gray-200 hover:bg-gray-300 text-gray-800 font-medium rounded-md shadow-sm dark:bg-gray-700 dark:text-white dark:hover:bg-gray-600">
            {{ isMockMode() ? 'Disable' : 'Enable' }} Mock Mode
          </button>
          <p class="mt-2 text-sm text-gray-500 dark:text-gray-400">
            Mock mode simulates biometric auth for testing when real biometrics aren't available.
          </p>
        </div>
      }
    </div>
  `,
  styles: [`
    /* Add any component-specific styles here */
  `]
})
export class BiometricSetupComponent {
  private biometricService = inject(BiometricAuthService);

  // State signals
  protected isLoading = signal(true);
  protected errorMessage = signal<string | null>(null);
  protected biometricCapability = signal<{isAvailable: boolean; type: string | null} | null>(null);
  protected isSetupComplete = signal(false);
  protected isMockMode = signal(false);

  // Debug flag - set to true only in development
  protected showDebugOptions = signal(false);

  constructor() {
    // Check if the device supports biometric auth
    this.checkBiometricCapabilities();

    // Check if mock mode is enabled
    this.isMockMode.set(localStorage.getItem('biometric_mock_mode') === 'true');

    // For development environment only
    if (location.hostname === 'localhost' || location.hostname === '127.0.0.1') {
      this.showDebugOptions.set(true);
    }
  }

  /**
   * Checks if biometric authentication is registered
   *
   * @returns True if biometric credentials are registered
   */
  protected isBiometricRegistered(): boolean {
    return this.biometricService.hasBiometricToken();
  }

  /**
   * Checks if biometric authentication is enabled
   *
   * @returns True if biometric authentication is enabled
   */
  protected isBiometricEnabled(): boolean {
    return this.biometricService.isBiometricEnabled();
  }

  /**
   * Gets a user-friendly label for the biometric type
   *
   * @param type The biometric type from the capability check
   * @returns A user-friendly label
   */
  protected getBiometricTypeLabel(type: string | null): string {
    switch(type) {
      case 'fingerprint': return 'Fingerprint';
      case 'face': return 'Face Recognition';
      default: return 'Biometric';
    }
  }

  /**
   * Checks the device's biometric capabilities
   */
  private async checkBiometricCapabilities(): Promise<void> {
    this.isLoading.set(true);
    this.errorMessage.set(null);

    try {
      const capability = await this.biometricService.getBiometricCapability();
      this.biometricCapability.set(capability);
    } catch (error: any) {
      this.errorMessage.set(`Error checking biometric capabilities: ${error.message}`);
      console.error('Error checking biometric capabilities:', error);
    } finally {
      this.isLoading.set(false);
    }
  }

  /**
   * Sets up biometric authentication
   */
  protected setupBiometric(): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);

    this.biometricService.setupBiometricLogin()
      .pipe(finalize(() => this.isLoading.set(false)))
      .subscribe({
        next: (success) => {
          if (success) {
            this.isSetupComplete.set(true);
          } else {
            this.errorMessage.set('Failed to setup biometric authentication.');
          }
        },
        error: (error) => {
          this.errorMessage.set(`Error setting up biometric authentication: ${error.message}`);
          console.error('Biometric setup error:', error);
        }
      });
  }

  /**
   * Toggles biometric authentication on/off
   *
   * @param event The change event from the toggle
   */
  protected toggleBiometric(event: Event): void {
    const isEnabled = (event.target as HTMLInputElement).checked;
    this.biometricService.setBiometricEnabled(isEnabled);
  }

  /**
   * Toggles mock mode for testing
   */
  protected toggleMockMode(): void {
    const newMockMode = !this.isMockMode();
    this.biometricService.enableMockBiometrics(newMockMode);
    this.isMockMode.set(newMockMode);

    // Refresh capabilities after toggling mock mode
    this.checkBiometricCapabilities();
  }
}
