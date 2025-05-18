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
import { IUser } from '../../interfaces/IUser';

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
   * Signal to track if biometrics are enabled for the current user
   * @signal
   */
  protected readonly isBiometricsEnabled = signal<boolean>(false);

  /**
   * Signal to track if we should show biometric setup prompt
   * @signal
   */
  protected readonly showBiometricSetupPrompt = signal<boolean>(false);

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
        const credData = JSON.parse(stored);
        // Only mark biometrics as enabled if we have valid data with a userId
        if (credData && credData.token && credData.userId) {
          console.log('Valid biometric token found for user:', credData.userId);
          this.isBiometricsEnabled.set(true);
        } else {
          console.log('Invalid biometric data format');
          this.isBiometricsEnabled.set(false);
        }
      } else {
        console.log('No biometric data found');
        this.isBiometricsEnabled.set(false);
      }
    } catch (error) {
      console.error('Error checking biometric token:', error);
      this.isBiometricsEnabled.set(false);
    }
  }

  /**
   * Checks if biometrics are enabled for a specific user
   * @param userId The user ID to check
   * @returns Whether biometrics are enabled for this user
   */
  private isBiometricsEnabledForUser(userId: string): boolean {
    try {
      const stored = localStorage.getItem(this.CREDENTIAL_KEY);
      if (!stored) return false;

      const credData = JSON.parse(stored);
      return credData && credData.userId === userId;
    } catch (error) {
      console.error('Error checking biometrics for user:', error);
      return false;
    }
  }

  /**
   * Detects device capabilities including WebAuthn and biometric support
   */
  private async detectDeviceCapabilities(): Promise<void> {
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
          // Try to determine what type of biometric is available
          // For simplicity, we'll use fingerprint as default
          // In a real app, we'd try to detect the specific type
          this.biometricType.set(BiometricType.FINGERPRINT);

          // On macOS or iOS devices with Face ID, we might want to use face
          if (navigator.platform.includes('Mac') ||
              /iPhone|iPad|iPod/.test(navigator.userAgent)) {
            this.biometricType.set(BiometricType.FACE);
          }

          console.log('Biometric type detected:', this.biometricType());
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

        // Generate a user ID based on email since IUser doesn't have an ID field
        const userIdForBiometrics = `user_${email}`;

        if (this.isPlatformAuthenticatorAvailable() && !this.isBiometricsEnabledForUser(userIdForBiometrics)) {
          console.log('Biometrics not enabled for user, showing setup prompt');
          this.showBiometricSetupPrompt.set(true);
          this.canRegisterBiometric.set(true);
        } else {
          this.navigationService.navigateToHome();
        }
      },
      error: (error) => {
        console.error('Login error:', error);
        this.errorMessage.set('Invalid email or password. Please try again.');
        this.isLoading.set(false);
      }
    });
  }

  /**
   * Dismisses the biometric setup prompt and continues to home
   */
  skipBiometricSetup(): void {
    this.showBiometricSetupPrompt.set(false);
    this.navigationService.navigateToHome();
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
  private saveCredentialLocally(credential: PublicKeyCredential, userId: string): void {
    const user = this.authService.currentUserSig();
    if (!user) {
      throw new Error('No authenticated user found');
    }

    const credData = {
      id: credential.id,
      type: credential.type,
      rawId: this.arrayBufferToBase64(credential.rawId),
      // Store the user ID to link this credential to a specific user
      userId: userId,
      // For a real app, this would be a real token from your backend
      token: btoa(user.username || 'demo-user'),
    };

    try {
      localStorage.setItem(this.CREDENTIAL_KEY, JSON.stringify(credData));
      console.log('Credential saved locally for user:', userId);
      this.isBiometricsEnabled.set(true);
    } catch (error) {
      console.error('Error saving credential:', error);
      throw error;
    }
  }

  /**
   * Removes the stored biometric credential for the current user
   */
  disableBiometrics(): void {
    try {
      localStorage.removeItem(this.CREDENTIAL_KEY);
      this.isBiometricsEnabled.set(false);
      this.errorMessage.set('Biometric authentication has been disabled.');
      console.log('Biometrics disabled');
    } catch (error) {
      console.error('Error disabling biometrics:', error);
      this.errorMessage.set('Failed to disable biometric authentication.');
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
    this.showBiometricSetupPrompt.set(false);

    try {
      const challenge = this.generateChallenge();
      // Generate a user ID from email since IUser doesn't have an ID field
      const userId = `user_${user.email}`;

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
          this.saveCredentialLocally(pubKeyCredential, userId);

          console.log('Biometric registration successful');
          this.isLoading.set(false);

          if (this.showBiometricSetupPrompt()) {
            // If this was during initial setup, navigate to home
            this.navigationService.navigateToHome();
          } else {
            // Otherwise show success message
            this.errorMessage.set('Biometric credential registered successfully! You can now use biometric authentication.');
          }
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

          if (this.showBiometricSetupPrompt()) {
            // If this was during initial setup, continue to home anyway
            this.navigationService.navigateToHome();
          }
        });
    } catch (error: any) {
      console.error('Error initiating biometric registration:', error);
      this.errorMessage.set('Failed to initiate biometric registration: ' + error.message);
      this.isLoading.set(false);

      if (this.showBiometricSetupPrompt()) {
        // If this was during initial setup, continue to home anyway
        this.navigationService.navigateToHome();
      }
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
          // Here we just use the stored user ID to log the user in
          if (credData.userId) {
            // In a real app, you would validate this token with your backend
            console.log('User authenticated with ID:', credData.userId);

            // Tell the auth service about the biometric authentication
            this.authService.setAuthenticatedUserFromToken(credData.userId);
          }

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
