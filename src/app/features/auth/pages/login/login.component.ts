/**
 * @fileoverview Login component implementation.
 *
 * This component handles user authentication through a login form with WebAuthn biometric support.
 */
import { Component, inject, signal, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, Validators } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { NavigationService } from '../../services/navigation.service';
import { BiometricAuthService } from '../../services/biometric-auth.service';
import { Subscription } from 'rxjs';

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
export class LoginComponent implements OnInit, OnDestroy {
  private fb = inject(FormBuilder);
  private authService = inject(AuthService);
  private navigationService = inject(NavigationService);
  private biometricAuthService = inject(BiometricAuthService);
  private subscription = new Subscription();

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
   * Signal to track if the user is on a mobile or tablet device.
   * @signal
   */
  protected readonly isMobileOrTablet = signal<boolean>(false);

  /**
   * Signal to track if WebAuthn is available on this device.
   * @signal
   */
  protected readonly isWebAuthnSupported = signal<boolean>(false);

  /**
   * Signal to track if platform authenticator is available.
   * @signal
   */
  protected readonly isPlatformAuthenticatorAvailable = signal<boolean>(false);

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
   * Signal to track if mock biometric mode is enabled
   * @signal
   */
  protected readonly isMockBiometricMode = signal<boolean>(false);

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
    this.detectDeviceCapabilities();
    this.checkForExistingBiometricToken();

    // Check if mock mode is enabled
    try {
      const mockMode = localStorage.getItem('biometric_mock_mode');
      this.isMockBiometricMode.set(mockMode === 'true');
    } catch (error) {
      console.error('Error checking mock biometric mode:', error);
    }
  }

  /**
   * Clean up subscriptions when component is destroyed
   */
  ngOnDestroy(): void {
    this.subscription.unsubscribe();
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
   * Detects device capabilities including mobile/tablet status and biometric support
   */
  private async detectDeviceCapabilities(): Promise<void> {
    // Check if device is mobile or tablet
    const isMobileOrTablet = this.biometricAuthService.isMobileOrTablet();
    this.isMobileOrTablet.set(isMobileOrTablet);
    console.log('Mobile or tablet device detected:', isMobileOrTablet);

    // Check if WebAuthn is supported
    const isWebAuthnSupported = this.biometricAuthService.isBiometricSupported();
    this.isWebAuthnSupported.set(isWebAuthnSupported);
    console.log('WebAuthn supported:', isWebAuthnSupported);

    if (isWebAuthnSupported) {
      try {
        // Check if platform authenticator is available
        const isPlatformAuthAvailable = await this.biometricAuthService.isPlatformAuthenticatorAvailable();
        this.isPlatformAuthenticatorAvailable.set(isPlatformAuthAvailable);
        console.log('Platform authenticator available:', isPlatformAuthAvailable);

        if (isPlatformAuthAvailable) {
          // Get detailed biometric capability information
          const capabilityInfo = await this.biometricAuthService.getBiometricCapability();
          if (capabilityInfo.isAvailable && capabilityInfo.type) {
            this.biometricType.set(capabilityInfo.type as BiometricType);
            console.log('Biometric type detected:', capabilityInfo.type);
          }
        }
      } catch (error) {
        console.error('Error detecting biometric capabilities:', error);
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
        this.canRegisterBiometric.set(this.isPlatformAuthenticatorAvailable());
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

    // Test localStorage first to make sure it's working
    try {
      const testKey = 'webauthn_test';
      localStorage.setItem(testKey, 'test');
      localStorage.removeItem(testKey);
    } catch (error: any) {
      console.error('localStorage error before biometric registration:', error);
      this.errorMessage.set('Cannot register biometrics: localStorage is not available. ' +
        'This could be due to private browsing mode, cookies being disabled, or storage limits.');
      return;
    }

    this.isLoading.set(true);
    this.errorMessage.set(null);

    // Generate a unique user ID for this credential
    const userId = `user_${Math.random().toString(36).substring(2, 10)}`;

    this.subscription.add(
      this.biometricAuthService.registerBiometricCredential(
        user.username,
        userId
      ).subscribe({
        next: () => {
          console.log('Biometric registration successful');
          this.isLoading.set(false);
          this.errorMessage.set('Biometric credential registered successfully! You can now use biometric authentication.');
        },
        error: (error) => {
          console.error('Biometric registration error:', error);

          // Check for specific WebAuthn errors
          let errorMessage = 'Failed to register biometric: ' + error.message;

          if (error.name === 'NotAllowedError') {
            errorMessage = 'Registration was declined by the user or the device.';
          } else if (error.name === 'SecurityError') {
            errorMessage = 'The operation is not allowed due to security restrictions.';
          } else if (error.message && error.message.includes('localStorage')) {
            errorMessage = 'Cannot save biometric data. Storage might be disabled or full.';
          }

          this.errorMessage.set(errorMessage);
          this.isLoading.set(false);
        }
      })
    );
  }

  /**
   * Handles biometric authentication using WebAuthn
   */
  loginWithBiometrics(): void {
    console.log('Attempting biometric authentication...');

    // Test localStorage first to make sure it's working
    try {
      const testKey = 'webauthn_test';
      const storedCredential = localStorage.getItem(this.biometricAuthService['CREDENTIAL_KEY']);
      if (!storedCredential) {
        this.errorMessage.set('No biometric credential found. Please register first.');
        return;
      }
    } catch (error: any) {
      console.error('localStorage error before biometric authentication:', error);
      this.errorMessage.set('Cannot authenticate: localStorage is not available. ' +
        'This could be due to private browsing mode, cookies being disabled, or storage limits.');
      return;
    }

    this.isLoading.set(true);
    this.errorMessage.set(null);

    this.subscription.add(
      this.biometricAuthService.authenticateWithBiometrics().subscribe({
        next: () => {
          console.log('Biometric authentication successful, navigating to home');
          this.isLoading.set(false);
          this.navigationService.navigateToHome();
        },
        error: (error) => {
          console.error('Biometric authentication error:', error);

          // Check for specific WebAuthn errors
          let errorMessage = 'Biometric authentication failed. Please try again or use password.';

          if (error.name === 'NotAllowedError') {
            errorMessage = 'Authentication was declined by the user or the device.';
          } else if (error.name === 'SecurityError') {
            errorMessage = 'The operation is not allowed due to security restrictions.';
          } else if (error.message && error.message.includes('localStorage')) {
            errorMessage = 'Cannot access biometric data. Storage might be disabled or full.';
          }

          this.errorMessage.set(errorMessage);
          this.isLoading.set(false);
        }
      })
    );
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
