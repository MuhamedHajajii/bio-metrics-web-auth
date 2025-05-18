/**
 * @fileoverview Login component implementation.
 *
 * This component handles user authentication through a login form with WebAuthn biometric support.
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
 * Provides a form for users to authenticate with email and password or biometrics.
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
   * Signal to track if WebAuthn is available on this device.
   * @signal
   */
  protected readonly isWebAuthnSupported = signal<boolean>(false);

  /**
   * Signal to track what type of biometric authentication is available.
   * @signal
   */
  protected readonly biometricType = signal<BiometricType>(BiometricType.NONE);

  /**
   * Signal to track if biometric registration is available.
   * @signal
   */
  protected readonly canRegisterBiometric = signal<boolean>(false);

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
    this.detectBiometricCapabilities();
    this.checkForExistingBiometricToken();
  }

  /**
   * Checks if there's an existing valid biometric token
   * and automatically logs in if one exists
   */
  private checkForExistingBiometricToken(): void {
    // Check if there's a valid token
    console.log('Checking for existing biometric token...');
    if (this.biometricAuthService.hasBiometricToken()) {
      console.log('Valid biometric token found, attempting login...');

      // Show loading state
      this.isLoading.set(true);

      // Attempt login with stored token
      if (this.biometricAuthService.loginWithStoredToken()) {
        console.log('Successfully logged in with biometric token, redirecting to home');

        // Simulate a brief delay for better UX
        setTimeout(() => {
          this.isLoading.set(false);
          this.navigationService.navigateToHome();
        }, 1000);
      } else {
        console.log('Failed to log in with biometric token');
        this.isLoading.set(false);
        this.errorMessage.set('Automatic login failed. Please log in manually.');
      }
    } else {
      console.log('No valid biometric token found');
    }
  }

  /**
   * Detects available biometric capabilities using WebAuthn
   */
  private detectBiometricCapabilities(): void {
    // Check if WebAuthn is supported in this browser
    const isSupported = this.biometricAuthService.isBiometricSupported();
    this.isWebAuthnSupported.set(isSupported);
    console.log('WebAuthn supported:', isSupported);

    if (isSupported) {
      // Determine biometric type based on user agent
      const userAgent = navigator.userAgent.toLowerCase();

      if (userAgent.includes('iphone') || userAgent.includes('ipad') || userAgent.includes('mac')) {
        // iOS/macOS devices typically have Face ID or Touch ID
        const isRecent = /iPhone X|iPhone 1[1-9]|iPhone 2[0-9]/.test(navigator.userAgent);
        this.biometricType.set(isRecent ? BiometricType.FACE : BiometricType.FINGERPRINT);
      } else if (userAgent.includes('android')) {
        // Most Android devices have fingerprint sensors
        this.biometricType.set(BiometricType.FINGERPRINT);
      } else if (navigator.platform.includes('Win')) {
        // Windows devices with Windows Hello
        this.biometricType.set(BiometricType.FACE);
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
        this.canRegisterBiometric.set(this.isWebAuthnSupported());
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
   * Registers the user's biometric credentials after successful login
   */
  registerBiometrics(): void {
    const user = this.authService.currentUserSig();
    if (!user) {
      this.errorMessage.set('You must be logged in to register biometrics');
      return;
    }

    this.isLoading.set(true);
    this.errorMessage.set(null);

    // Generate a unique user ID for this credential
    const userId = `user_${Math.random().toString(36).substring(2, 10)}`;

    this.biometricAuthService.registerBiometricCredential(
      user.username,
      userId
    ).subscribe({
      next: () => {
        console.log('Biometric registration successful');
        this.isLoading.set(false);
        this.errorMessage.set(null);
      },
      error: (error) => {
        console.error('Biometric registration error:', error);
        this.errorMessage.set('Failed to register biometric: ' + error.message);
        this.isLoading.set(false);
      }
    });
  }

  /**
   * Handles biometric authentication using WebAuthn
   */
  loginWithBiometrics(): void {
    console.log('Attempting biometric authentication...');
    this.isLoading.set(true);
    this.errorMessage.set(null);

    this.biometricAuthService.authenticateWithBiometrics().subscribe({
      next: () => {
        console.log('Biometric authentication successful, navigating to home');
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
