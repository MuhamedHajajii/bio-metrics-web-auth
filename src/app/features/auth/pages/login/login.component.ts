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
   * Local storage key for WebAuthn credential
   * @private
   */
  private readonly CREDENTIAL_KEY = 'webauthnCredential';

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
    console.log('Checking for existing biometric token...');
    try {
      const stored = localStorage.getItem(this.CREDENTIAL_KEY);
      if (stored) {
        console.log('Valid biometric token found, attempting login...');
        this.isLoading.set(true);

        // Get the token from the stored credential
        const credData = JSON.parse(stored);
        if (credData && credData.token) {
          // Use the token to authenticate the user
          const token = atob(credData.token);

          // Simulate a successful login using the token
          console.log('Successfully logged in with biometric token, redirecting to home');
          setTimeout(() => {
            this.isLoading.set(false);
            this.navigationService.navigateToHome();
          }, 1000);
        } else {
          console.log('Invalid biometric token format');
          this.isLoading.set(false);
          this.errorMessage.set('Automatic login failed. Please log in manually.');
        }
      } else {
        console.log('No valid biometric token found');
      }
    } catch (error) {
      console.error('Error checking biometric token:', error);
      this.errorMessage.set('Error checking biometric token. Please log in manually.');
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

    // Check if WebAuthn is supported by checking if navigator.credentials exists
    const isWebAuthnSupported = window.PublicKeyCredential !== undefined &&
                               navigator.credentials !== undefined;
    this.isWebAuthnSupported.set(isWebAuthnSupported);
    console.log('WebAuthn supported:', isWebAuthnSupported);

    if (isWebAuthnSupported) {
      try {
        // Check if platform authenticator is available
        const isPlatformAuthAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        this.isPlatformAuthenticatorAvailable.set(isPlatformAuthAvailable);
        console.log('Platform authenticator available:', isPlatformAuthAvailable);

        if (isPlatformAuthAvailable) {
          // For simplicity, assume fingerprint on most devices
          // In a real app, we could try to detect the specific biometric type
          this.biometricType.set(BiometricType.FINGERPRINT);
          console.log('Biometric type detected:', BiometricType.FINGERPRINT);
        }
      } catch (error) {
        console.error('Error detecting biometric capabilities:', error);
      }
    }

    // Check if there's a stored credential to determine if user can log in with biometrics
    try {
      const hasStoredCredential = localStorage.getItem(this.CREDENTIAL_KEY) !== null;
      console.log('Has stored biometric credential:', hasStoredCredential);
    } catch (error) {
      console.error('Error checking stored credentials:', error);
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
   * Helper: Encode string to Uint8Array
   */
  private strToUint8Array(str: string): Uint8Array {
    return new TextEncoder().encode(str);
  }

  /**
   * Helper: Convert ArrayBuffer to Base64 (for storage)
   */
  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    bytes.forEach(b => binary += String.fromCharCode(b));
    return window.btoa(binary);
  }

  /**
   * Helper: Convert Base64 to ArrayBuffer
   */
  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Generate random challenge
   */
  private generateChallenge(): Uint8Array {
    return window.crypto.getRandomValues(new Uint8Array(32));
  }

  /**
   * Save credential and token in localStorage
   */
  private saveCredentialLocally(credential: PublicKeyCredential): void {
    const user = this.authService.currentUserSig();
    const credData = {
      id: credential.id,
      type: credential.type,
      rawId: this.arrayBufferToBase64(credential.rawId),
      // For a real app, this would be a real token from your backend
      token: btoa(user?.username || 'demo-user'),
    };

    try {
      localStorage.setItem(this.CREDENTIAL_KEY, JSON.stringify(credData));
      console.log('Credential saved locally.');
    } catch (error) {
      console.error('Error saving credential:', error);
      throw error;
    }
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

    try {
      const challenge = this.generateChallenge();
      const userId = `user_${Math.random().toString(36).substring(2, 10)}`;

      // Create WebAuthn credential options
      const publicKeyOptions: PublicKeyCredentialCreationOptions = {
        challenge: challenge,
        rp: {
          name: 'Bio-Metrics Auth App',
        },
        user: {
          id: this.strToUint8Array(userId),
          name: user.username,
          displayName: user.username,
        },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }], // ES256 algorithm
        timeout: 60000,
        attestation: 'direct',
      };

      // Start the registration process
      navigator.credentials.create({ publicKey: publicKeyOptions })
        .then((credential) => {
          if (!credential) throw new Error('Credential creation failed');

          // Cast to the correct type
          const pubKeyCredential = credential as PublicKeyCredential;
          this.saveCredentialLocally(pubKeyCredential);

          console.log('Biometric registration successful');
          this.isLoading.set(false);
          this.errorMessage.set('Biometric credential registered successfully! You can now use biometric authentication.');
        })
        .catch((error) => {
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
        });
    } catch (error: any) {
      console.error('Error initiating biometric registration:', error);
      this.errorMessage.set('Failed to initiate biometric registration: ' + error.message);
      this.isLoading.set(false);
    }
  }

  /**
   * Handles biometric authentication using WebAuthn
   */
  loginWithBiometrics(): void {
    console.log('Attempting biometric authentication...');

    // Test localStorage first to make sure it's working
    try {
      const storedCredential = localStorage.getItem(this.CREDENTIAL_KEY);
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

    try {
      const stored = localStorage.getItem(this.CREDENTIAL_KEY);
      if (!stored) throw new Error('No credential stored. Please register first.');

      const credData = JSON.parse(stored);

      const publicKeyOptions: PublicKeyCredentialRequestOptions = {
        challenge: this.generateChallenge(),
        allowCredentials: [
          {
            id: this.base64ToArrayBuffer(credData.rawId),
            type: 'public-key',
          },
        ],
        timeout: 60000,
        userVerification: 'required', // forces biometric or PIN
      };

      navigator.credentials.get({ publicKey: publicKeyOptions })
        .then((assertion) => {
          if (!assertion) throw new Error('Authentication failed');

          console.log('Biometric authentication successful, navigating to home');

          // For a real app, you would verify the assertion with your backend
          // Here we just use the stored token from localStorage
          this.isLoading.set(false);
          this.navigationService.navigateToHome();
        })
        .catch((error) => {
          console.error('Biometric authentication error:', error);

          // Check for specific WebAuthn errors
          let errorMessage = 'Biometric authentication failed. Please try again or use password.';

          if (error.name === 'NotAllowedError') {
            errorMessage = 'Authentication was declined by the user or the device.';
          } else if (error.name === 'SecurityError') {
            errorMessage = 'The operation is not allowed due to security restrictions.';
          }

          this.errorMessage.set(errorMessage);
          this.isLoading.set(false);
        });
    } catch (error: any) {
      console.error('Error initiating biometric authentication:', error);
      this.errorMessage.set('Failed to initiate biometric authentication: ' + error.message);
      this.isLoading.set(false);
    }
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
