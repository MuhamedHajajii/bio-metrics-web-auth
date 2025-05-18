/**
 * @fileoverview Login component implementation.
 *
 * This component handles user authentication through a login form.
 */
import { Component, inject, signal, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, Validators } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { NavigationService } from '../../services/navigation.service';
import { BiometricAuthService } from '../../services/biometric-auth.service';

/**
 * Enum representing available biometric authentication methods
 */
export enum BiometricType {
  NONE = 'none',
  FINGERPRINT = 'fingerprint',
  FACE = 'face',
  OTHER = 'other'
}

/**
 * LoginComponent
 *
 * Provides a form for users to authenticate with email and password.
 *
 * @example
 * <app-login></app-login>
 */
@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule],
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss'
})
export class LoginComponent implements OnInit {
  private fb = inject(FormBuilder);
  private authService = inject(AuthService);
  private navigationService = inject(NavigationService);
  private biometricAuthService = inject(BiometricAuthService);

  /**
   * Signal to indicate if login is being processed.
   * @signal
   */
  protected readonly isLoading = signal<boolean>(false);

  /**
   * Signal to store error messages.
   * @signal
   */
  protected readonly errorMessage = signal<string | null>(null);

  /**
   * Signal to track if the user is on a mobile device.
   * @signal
   */
  protected readonly isMobile = signal<boolean>(false);

  /**
   * Signal to track what type of biometric authentication is available.
   * @signal
   */
  protected readonly biometricType = signal<BiometricType>(BiometricType.NONE);

  /**
   * The login form with validation.
   */
  protected loginForm = this.fb.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', [Validators.required, Validators.minLength(6)]]
  });

  /**
   * Initialize the component
   */
  ngOnInit(): void {
    this.detectMobile();
    this.detectBiometricCapabilities();
    this.checkForExistingBiometricToken();
  }

  /**
   * Checks if there's an existing valid biometric token
   * and automatically logs in if one exists
   */
  private checkForExistingBiometricToken(): void {
    if (this.biometricAuthService.hasBiometricToken()) {
      // Show loading state
      this.isLoading.set(true);

      // Attempt login with stored token
      if (this.biometricAuthService.loginWithStoredToken()) {
        // Simulate a brief delay for better UX
        setTimeout(() => {
          this.isLoading.set(false);
          this.navigationService.navigateToHome();
        }, 1000);
      } else {
        this.isLoading.set(false);
      }
    }
  }

  /**
   * Detects if the current device is mobile
   */
  private detectMobile(): void {
    // Basic mobile detection
    if (typeof window !== 'undefined') {
      const isMobileDevice = this.biometricAuthService.isBiometricSupported();
      this.isMobile.set(isMobileDevice);
    }
  }

  /**
   * Detects available biometric capabilities
   * This is a simplified detection - in a real app, we would use feature detection
   * with the WebAuthn/FIDO2 API or a specialized native bridge
   */
  private detectBiometricCapabilities(): void {
    // Simple OS-based detection (not accurate for real implementation)
    if (this.isMobile()) {
      const userAgent = navigator.userAgent.toLowerCase();

      if (userAgent.includes('iphone') || userAgent.includes('ipad')) {
        // iOS devices typically have Face ID or Touch ID
        const isRecent = /iPhone X|iPhone 1[1-9]|iPhone 2[0-9]/.test(navigator.userAgent);
        this.biometricType.set(isRecent ? BiometricType.FACE : BiometricType.FINGERPRINT);
      } else if (userAgent.includes('android')) {
        // Most Android devices have fingerprint sensors
        this.biometricType.set(BiometricType.FINGERPRINT);
      } else {
        this.biometricType.set(BiometricType.OTHER);
      }
    }
  }

  /**
   * Returns appropriate biometric authentication label based on detected capabilities
   */
  getBiometricLabel(): string {
    switch (this.biometricType()) {
      case BiometricType.FACE:
        return 'Sign in with Face ID';
      case BiometricType.FINGERPRINT:
        return 'Sign in with Fingerprint';
      default:
        return 'Sign in with Biometrics';
    }
  }

  /**
   * Handles the login form submission.
   */
  onSubmit(): void {
    if (this.loginForm.invalid) {
      return;
    }

    this.isLoading.set(true);
    this.errorMessage.set(null);

    const email = this.loginForm.get('email')?.value;
    const password = this.loginForm.get('password')?.value;

    if (!email || !password) {
      this.errorMessage.set('Email and password are required');
      this.isLoading.set(false);
      return;
    }

    this.authService.login(email, password).subscribe({
      next: () => {
        this.isLoading.set(false);
        this.navigationService.navigateToHome();
      },
      error: (error) => {
        console.error('Login error:', error);
        this.errorMessage.set('Invalid email or password. Please try again.');
        this.isLoading.set(false);
      }
    });
  }

  /**
   * Handles biometric authentication for mobile devices
   */
  loginWithBiometrics(): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);

    this.biometricAuthService.authenticateWithBiometrics().subscribe({
      next: () => {
        this.isLoading.set(false);
        this.navigationService.navigateToHome();
      },
      error: (error) => {
        console.error('Biometric authentication error:', error);
        this.errorMessage.set('Biometric authentication failed. Please try again or use password.');
        this.isLoading.set(false);
      }
    });
  }

  /**
   * Navigates to the registration page.
   */
  goToRegister(): void {
    this.navigationService.navigateToRegister();
  }

  /**
   * Navigates to the reset password page.
   */
  goToResetPassword(): void {
    this.navigationService.navigateToResetPassword();
  }
}
