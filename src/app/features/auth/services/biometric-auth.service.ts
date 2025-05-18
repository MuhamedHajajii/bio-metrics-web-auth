/**
 * @fileoverview Biometric authentication service using WebAuthn API.
 *
 * Handles biometric authentication via fingerprint or Face ID without requiring backend integration.
 * Includes a fallback mock implementation for testing when WebAuthn isn't available.
 */
import { Injectable, PLATFORM_ID, inject } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, of, throwError, from } from 'rxjs';
import { delay, tap, catchError, map, switchMap, finalize } from 'rxjs/operators';
import { AuthService } from './auth.service';
import { NavigationService } from './navigation.service';
import { isPlatformBrowser } from '@angular/common';
import { DeviceDetectorService } from 'ngx-device-detector';
import { HttpClient } from '@angular/common/http';

/**
 * Token interface defining the structure of authentication tokens
 */
interface AuthToken {
  token: string;
  expiresAt: number;
  userId: string;
  email: string;
  username: string;
  credentialId?: string; // Store WebAuthn credential ID
}

/**
 * Device capability information for biometric features
 */
interface BiometricCapability {
  isAvailable: boolean;
  type: 'fingerprint' | 'face' | 'other' | null;
}

/**
 * BiometricAuthService
 *
 * Manages biometric authentication using WebAuthn API for seamless fingerprint/Face ID login.
 * Includes fallback mock implementation for testing when WebAuthn isn't available.
 */
@Injectable({
  providedIn: 'root'
})
export class BiometricAuthService {
  private readonly TOKEN_KEY = 'biometric_auth_token';
  private readonly CREDENTIAL_KEY = 'webauthn_credential_id';
  private readonly MOCK_MODE_KEY = 'biometric_mock_mode';
  private readonly BIOMETRIC_ENABLED_KEY = 'biometric_auth_enabled';
  private authService = inject(AuthService);
  private platformId = inject(PLATFORM_ID);
  private deviceService = inject(DeviceDetectorService);
  private router = inject(Router);
  private navigation = inject(NavigationService);
  private http = inject(HttpClient);

  // Flag to use mock implementation when WebAuthn isn't working
  private useMockImplementation = false;

  constructor() {
    // Check if we can access localStorage
    this.testLocalStorage();

    // Check if mock mode was previously enabled
    if (isPlatformBrowser(this.platformId)) {
      try {
        const mockMode = localStorage.getItem(this.MOCK_MODE_KEY);
        this.useMockImplementation = mockMode === 'true';
        console.log('Mock biometric mode:', this.useMockImplementation);
      } catch (error: any) {
        console.error('Error checking mock mode:', error);
      }
    }
  }

  /**
   * Enable or disable mock biometric implementation
   *
   * @param enable Whether to enable mock mode
   */
  enableMockBiometrics(enable: boolean): void {
    this.useMockImplementation = enable;
    try {
      localStorage.setItem(this.MOCK_MODE_KEY, enable ? 'true' : 'false');
      console.log('Mock biometric mode set to:', enable);
    } catch (error: any) {
      console.error('Error setting mock mode:', error);
    }
  }

  /**
   * Tests if localStorage is accessible
   */
  private testLocalStorage(): void {
    if (!isPlatformBrowser(this.platformId)) {
      console.log('Not a browser environment, localStorage not available');
      return;
    }

    try {
      // Try to write and read from localStorage
      localStorage.setItem('test_storage', 'test');
      const testValue = localStorage.getItem('test_storage');
      localStorage.removeItem('test_storage');

      if (testValue === 'test') {
        console.log('localStorage is working correctly');
      } else {
        console.error('localStorage set/get test failed');
      }
    } catch (error: any) {
      console.error('Error accessing localStorage:', error);
    }
  }

  /**
   * Determines if the current device is a mobile phone or tablet
   *
   * @returns True if the device is a mobile phone or tablet
   */
  isMobileOrTablet(): boolean {
    if (!isPlatformBrowser(this.platformId)) {
      return false;
    }

    return this.deviceService.isMobile() || this.deviceService.isTablet();
  }

  /**
   * Determines if the current device supports biometric authentication
   *
   * @returns True if biometric authentication is supported or mock mode is enabled
   */
  isBiometricSupported(): boolean {
    if (this.useMockImplementation) {
      console.log('Using mock biometric implementation');
      return true;
    }

    if (!isPlatformBrowser(this.platformId)) {
      return false;
    }

    // Check if WebAuthn is available in this browser
    const isSupported = window.PublicKeyCredential !== undefined;
    console.log('WebAuthn API supported:', isSupported);
    return isSupported;
  }

  /**
   * Checks if platform authenticator is available (like fingerprint or Face ID)
   *
   * @returns Promise resolving to true if platform authenticator is available or mock mode is enabled
   */
  async isPlatformAuthenticatorAvailable(): Promise<boolean> {
    if (this.useMockImplementation) {
      console.log('Mock biometric platform authenticator is available');
      return true;
    }

    if (!this.isBiometricSupported()) {
      console.log('Biometric not supported, skipping platform authenticator check');
      return false;
    }

    try {
      // This is a modern way to check if platform authenticator is available
      const isAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      console.log('Platform authenticator available:', isAvailable);
      return isAvailable;
    } catch (error: any) {
      console.error('Error checking platform authenticator:', error);
      return false;
    }
  }

  /**
   * Get detailed biometric capability information
   *
   * @returns Promise resolving to biometric capability information
   */
  async getBiometricCapability(): Promise<BiometricCapability> {
    if (this.useMockImplementation) {
      // For mock mode, return the device-appropriate biometric type
      const userAgent = navigator.userAgent.toLowerCase();
      let type: 'fingerprint' | 'face' | 'other' = 'other';

      if (userAgent.includes('iphone') || userAgent.includes('ipad')) {
        type = /iPhone X|iPhone 1[1-9]|iPhone 2[0-9]/.test(navigator.userAgent)
          ? 'face'
          : 'fingerprint';
      } else if (userAgent.includes('android')) {
        type = 'fingerprint';
      } else if (navigator.platform.includes('Win')) {
        type = 'face';
      }

      console.log('Mock biometric type:', type);
      return { isAvailable: true, type };
    }

    if (!this.isBiometricSupported()) {
      return { isAvailable: false, type: null };
    }

    try {
      const isPlatformAuthAvailable = await this.isPlatformAuthenticatorAvailable();

      if (!isPlatformAuthAvailable) {
        return { isAvailable: false, type: null };
      }

      // Determine the likely biometric type based on the device
      const userAgent = navigator.userAgent.toLowerCase();
      let type: 'fingerprint' | 'face' | 'other' = 'other';

      if (userAgent.includes('iphone') || userAgent.includes('ipad')) {
        // Modern iPhones have Face ID, older ones have Touch ID
        type = /iPhone X|iPhone 1[1-9]|iPhone 2[0-9]/.test(navigator.userAgent)
          ? 'face'
          : 'fingerprint';
      } else if (userAgent.includes('android')) {
        // Most Android devices use fingerprint
        type = 'fingerprint';
      } else if (navigator.platform.includes('Win')) {
        // Windows Hello generally uses facial recognition
        type = 'face';
      }

      console.log('Detected biometric type:', type);
      return { isAvailable: true, type };
    } catch (error: any) {
      console.error('Error determining biometric capability:', error);
      return { isAvailable: false, type: null };
    }
  }

  /**
   * Checks if a biometric token exists and is valid
   *
   * @returns True if a valid token exists
   */
  hasBiometricToken(): boolean {
    const tokenData = this.getStoredToken();
    if (!tokenData) {
      console.log('No token found in localStorage');
      return false;
    }

    // Check if token is expired
    const isValid = tokenData.expiresAt > Date.now();
    console.log('Token found, valid:', isValid, 'expires:', new Date(tokenData.expiresAt).toLocaleString());
    return isValid;
  }

  /**
   * Registers the user's biometric credential (fingerprint/Face ID)
   *
   * @param username The username to associate with the credential
   * @param userId A unique user identifier
   * @returns An Observable that resolves when registration is complete
   */
  registerBiometricCredential(username: string, userId: string): Observable<boolean> {
    console.log('Starting biometric registration process for user:', username);

    // Use mock implementation if needed
    if (this.useMockImplementation) {
      console.log('Using mock biometric registration');

      return of(true).pipe(
        delay(1500), // Simulate biometric verification delay
        tap(() => {
          try {
            // Create a mock token
            const token: AuthToken = {
              token: 'mock_webauthn_' + Math.random().toString(36).substring(2, 15),
              expiresAt: Date.now() + (30 * 24 * 60 * 60 * 1000), // 30 days
              userId: userId,
              email: `${username}@example.com`,
              username: username,
              credentialId: 'mock_credential_' + Math.random().toString(36).substring(2, 15)
            };

            // Store the mock token and credential ID
            this.storeToken(token);
            localStorage.setItem(this.CREDENTIAL_KEY, token.credentialId!);
            console.log('Mock biometric registration successful', token.credentialId);
          } catch (error: any) {
            console.error('Error storing mock biometric credentials:', error);
            throw new Error('Failed to store mock credentials: ' + error.message);
          }
        })
      );
    }

    if (!this.isBiometricSupported()) {
      return throwError(() => new Error('WebAuthn is not supported in this browser'));
    }

    // Check if platform authenticator is available
    return from(this.isPlatformAuthenticatorAvailable()).pipe(
      switchMap(isPlatformAvailable => {
        if (!isPlatformAvailable) {
          return throwError(() => new Error('No platform authenticator (like fingerprint or Face ID) is available'));
        }

        // Generate a random challenge
        const challenge = this.generateRandomChallenge();
        console.log('Created challenge for registration');

        // Prepare creation options according to WebAuthn spec
        const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
          challenge: challenge,
          rp: {
            name: "Your App Name",
            id: window.location.hostname
          },
          user: {
            id: new TextEncoder().encode(userId),
            name: username,
            displayName: username
          },
          pubKeyCredParams: [
            { type: "public-key", alg: -7 }, // ES256 algorithm
            { type: "public-key", alg: -257 } // RS256 algorithm
          ],
          authenticatorSelection: {
            authenticatorAttachment: "platform", // Use platform authenticator (like Touch ID or Face ID)
            userVerification: "required", // Require biometric verification
            requireResidentKey: false
          },
          timeout: 60000,
          attestation: "none" // Don't require attestation to simplify
        };

        console.log('Using hostname for RP ID:', window.location.hostname);
        console.log('Requesting credential creation with options:', JSON.stringify(publicKeyCredentialCreationOptions));

        // Call WebAuthn create() method to register the credential
        return from(navigator.credentials.create({
          publicKey: publicKeyCredentialCreationOptions
        }) as Promise<PublicKeyCredential>).pipe(
          map(credential => {
            console.log('WebAuthn credential created successfully');
            // Store the credential ID for later authentication
            const rawId = new Uint8Array(credential.rawId);
            const credentialId = this.bufferToBase64UrlString(rawId);
            console.log('Credential ID:', credentialId);

            // Generate a mock token with the credential ID
            const token: AuthToken = {
              token: 'webauthn_auth_' + Math.random().toString(36).substring(2, 15),
              expiresAt: Date.now() + (30 * 24 * 60 * 60 * 1000), // 30 days
              userId: userId,
              email: `${username}@example.com`, // Mock email
              username: username,
              credentialId: credentialId
            };

            console.log('Storing token:', JSON.stringify(token));

            // Store the token and credential ID
            try {
              this.storeToken(token);

              // Verify token was stored
              const storedToken = this.getStoredToken();
              if (!storedToken) {
                console.error('Failed to store token - not found after save');
              } else {
                console.log('Token successfully stored and verified');
              }

              // Store credential ID
              localStorage.setItem(this.CREDENTIAL_KEY, credentialId);

              // Verify credential ID was stored
              const storedCredId = localStorage.getItem(this.CREDENTIAL_KEY);
              if (storedCredId !== credentialId) {
                console.error('Failed to store credential ID - value mismatch', storedCredId);
              } else {
                console.log('Credential ID successfully stored and verified');
              }

              console.log('Biometric credential registered successfully');
              return true;
            } catch (error: any) {
              console.error('Error storing credential data:', error);
              throw new Error('Failed to store credential data: ' + error.message);
            }
          }),
          catchError(error => {
            console.error('Error registering credential:', error);
            return throwError(() => new Error('Failed to register biometric credential: ' + error.message));
          })
        );
      })
    );
  }

  /**
   * Authenticates the user using biometrics (fingerprint/Face ID)
   *
   * @returns An Observable that resolves to a success value on successful authentication
   */
  authenticateWithBiometrics(): Observable<boolean> {
    console.log('Starting biometric authentication process');

    // Use mock implementation if needed
    if (this.useMockImplementation) {
      console.log('Using mock biometric authentication');

      return of(true).pipe(
        delay(1500), // Simulate biometric verification delay
        tap(() => {
          try {
            // Check if we have a mock token
            const token = this.getStoredToken();
            if (!token) {
              throw new Error('No token found. Please register first.');
            }

            // Update token expiration
            token.expiresAt = Date.now() + (30 * 24 * 60 * 60 * 1000); // 30 days
            this.storeToken(token);

            // Authenticate the user
            this.authService.setAuthenticatedUserFromToken(
              token.userId,
              token.email,
              token.username
            );

            console.log('Mock biometric authentication successful');
          } catch (error: any) {
            console.error('Error in mock biometric authentication:', error);
            throw new Error('Mock authentication failed: ' + error.message);
          }
        })
      );
    }

    if (!this.isBiometricSupported()) {
      return throwError(() => new Error('WebAuthn is not supported in this browser'));
    }

    // Get stored credential ID if available
    const credentialId = localStorage.getItem(this.CREDENTIAL_KEY);
    if (!credentialId) {
      console.error('No stored credential ID found in localStorage');
      return throwError(() => new Error('No biometric credential found. Please register first.'));
    }

    console.log('Found stored credential ID:', credentialId);

    // Generate a random challenge
    const challenge = this.generateRandomChallenge();

    // Prepare request options according to WebAuthn spec
    const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
      challenge: challenge,
      allowCredentials: [{
        id: this.base64UrlStringToBuffer(credentialId),
        type: 'public-key',
        transports: ['internal']
      }],
      timeout: 60000,
      userVerification: 'required' // Require biometric verification
    };

    console.log('Requesting credential with options:', JSON.stringify(publicKeyCredentialRequestOptions));

    // Call WebAuthn get() method to authenticate
    return from(navigator.credentials.get({
      publicKey: publicKeyCredentialRequestOptions
    }) as Promise<PublicKeyCredential>).pipe(
      map(assertion => {
        console.log('WebAuthn authentication successful');
        // Authentication succeeded - retrieve and update the stored token
        const token = this.getStoredToken();

        if (token) {
          // Update token expiration
          token.expiresAt = Date.now() + (30 * 24 * 60 * 60 * 1000); // 30 days

          try {
            this.storeToken(token);
            console.log('Token updated with new expiration');

            // Update authentication state in AuthService
            this.authService.setAuthenticatedUserFromToken(
              token.userId,
              token.email,
              token.username
            );

            console.log('Biometric authentication successful');
            return true;
          } catch (error: any) {
            console.error('Error updating token:', error);
            throw new Error('Error updating token: ' + error.message);
          }
        } else {
          console.error('Token not found after successful authentication');
          throw new Error('Token not found after successful authentication');
        }
      }),
      catchError(error => {
        console.error('Biometric authentication failed:', error);
        return throwError(() => new Error('Biometric authentication failed: ' + error.message));
      })
    );
  }

  /**
   * Attempts to login using a stored biometric token
   *
   * @returns True if successfully authenticated with token
   */
  loginWithStoredToken(): boolean {
    console.log('Attempting to login with stored token');

    if (this.hasBiometricToken()) {
      const token = this.getStoredToken();
      if (token) {
        console.log('Using token to authenticate:', token);

        // Update authentication state in AuthService
        this.authService.setAuthenticatedUserFromToken(
          token.userId,
          token.email || `${token.userId}@example.com`,
          token.username || `User ${token.userId.slice(-4)}`
        );
        console.log('Successfully logged in with stored biometric token');
        return true;
      }
    }
    console.log('No valid biometric token found');
    return false;
  }

  /**
   * Clears any stored biometric tokens and credentials
   */
  clearBiometricToken(): void {
    try {
      localStorage.removeItem(this.TOKEN_KEY);
      localStorage.removeItem(this.CREDENTIAL_KEY);
      console.log('Biometric token and credential cleared');
    } catch (error: any) {
      console.error('Error clearing biometric tokens:', error);
    }
  }

  /**
   * Generates a random challenge for WebAuthn operations
   *
   * @returns A Uint8Array containing random bytes
   */
  private generateRandomChallenge(): Uint8Array {
    const challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    return challenge;
  }

  /**
   * Converts a buffer to a Base64URL string
   *
   * @param buffer The buffer to convert
   * @returns A Base64URL encoded string
   */
  private bufferToBase64UrlString(buffer: Uint8Array): string {
    const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /**
   * Converts a Base64URL string to a buffer
   *
   * @param base64url The Base64URL string to convert
   * @returns A Uint8Array buffer
   */
  private base64UrlStringToBuffer(base64url: string): ArrayBuffer {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Stores an authentication token in localStorage
   *
   * @param token The token to store
   */
  private storeToken(token: AuthToken): void {
    if (!isPlatformBrowser(this.platformId)) {
      console.error('Cannot store token: not in browser environment');
      return;
    }

    try {
      const tokenJson = JSON.stringify(token);
      localStorage.setItem(this.TOKEN_KEY, tokenJson);
      console.log('Token stored successfully:', tokenJson);
    } catch (error: any) {
      console.error('Error storing token in localStorage:', error);
      throw new Error('Failed to store token: ' + error.message);
    }
  }

  /**
   * Retrieves the stored authentication token
   *
   * @returns The stored token or null if none exists
   */
  private getStoredToken(): AuthToken | null {
    if (!isPlatformBrowser(this.platformId)) {
      console.log('Not a browser environment, cannot retrieve token');
      return null;
    }

    try {
      const tokenJson = localStorage.getItem(this.TOKEN_KEY);
      if (!tokenJson) {
        console.log('No token found in localStorage');
        return null;
      }

      const token = JSON.parse(tokenJson) as AuthToken;
      console.log('Retrieved token:', token);
      return token;
    } catch (e: any) {
      console.error('Error parsing stored token:', e);
      return null;
    }
  }

  /**
   * Checks if the user has enabled biometric authentication
   *
   * @returns True if biometric authentication is enabled by the user
   */
  isBiometricEnabled(): boolean {
    if (!isPlatformBrowser(this.platformId)) {
      return false;
    }

    try {
      return localStorage.getItem(this.BIOMETRIC_ENABLED_KEY) === 'true';
    } catch (error: any) {
      console.error('Error checking biometric enabled status:', error);
      return false;
    }
  }

  /**
   * Enables or disables biometric authentication
   *
   * @param enable Whether to enable biometric authentication
   */
  setBiometricEnabled(enable: boolean): void {
    if (!isPlatformBrowser(this.platformId)) {
      return;
    }

    try {
      localStorage.setItem(this.BIOMETRIC_ENABLED_KEY, enable ? 'true' : 'false');
      console.log('Biometric authentication enabled:', enable);
    } catch (error: any) {
      console.error('Error setting biometric enabled status:', error);
    }
  }

  /**
   * Refreshes the stored token using the refresh token API
   *
   * @returns Observable that resolves to true if token was refreshed successfully
   */
  refreshTokenFromApi(): Observable<boolean> {
    console.log('Starting token refresh process');

    const token = this.getStoredToken();
    if (!token) {
      console.error('No token found to refresh');
      return throwError(() => new Error('No token found to refresh'));
    }

    // Get the current token to use as a refresh token
    const currentToken = token.token;

    // Call your API endpoint to refresh the token
    // Replace 'your-refresh-endpoint' with your actual endpoint
    return this.http.post<any>('/api/auth/refresh-token', { token: currentToken }).pipe(
      map(response => {
        if (!response || !response.token) {
          throw new Error('Invalid response from refresh token API');
        }

        // Update the stored token with the new one
        const newToken: AuthToken = {
          token: response.token,
          expiresAt: Date.now() + (response.expiresIn || 30 * 24 * 60 * 60 * 1000), // Default to 30 days if not specified
          userId: token.userId,
          email: token.email,
          username: token.username,
          credentialId: token.credentialId
        };

        try {
          this.storeToken(newToken);
          console.log('Token refreshed successfully');
          return true;
        } catch (error: any) {
          console.error('Error storing refreshed token:', error);
          throw error;
        }
      }),
      catchError(error => {
        console.error('Error refreshing token:', error);
        return throwError(() => new Error('Failed to refresh token: ' + error.message));
      })
    );
  }

  /**
   * Offers biometric login to the user and handles the complete flow
   *
   * @returns Observable that resolves when the biometric login process is complete
   */
  offerBiometricLogin(): Observable<boolean> {
    if (!this.isBiometricSupported() || !this.hasBiometricToken()) {
      console.log('Biometric login not available or no token stored');
      return of(false);
    }

    if (!this.isBiometricEnabled()) {
      console.log('Biometric authentication not enabled by user');
      return of(false);
    }

    console.log('Starting biometric login flow');

    // First authenticate with biometrics
    return this.authenticateWithBiometrics().pipe(
      switchMap(authenticated => {
        if (!authenticated) {
          console.log('Biometric authentication failed');
          return of(false);
        }

        // Biometric authentication succeeded, now refresh the token
        return this.refreshTokenFromApi().pipe(
          map(refreshed => {
            if (refreshed) {
              // Re-login with the fresh token
              if (this.loginWithStoredToken()) {
                console.log('Successfully logged in with refreshed token');
                return true;
              }
              console.error('Failed to login with refreshed token');
              return false;
            }
            console.error('Failed to refresh token');
            return false;
          }),
          catchError(error => {
            console.error('Error during token refresh after biometric auth:', error);
            // Even if refresh failed, we may still want to try using the existing token
            if (this.loginWithStoredToken()) {
              console.log('Logged in with existing token despite refresh failure');
              return of(true);
            }
            return of(false);
          })
        );
      })
    );
  }

  /**
   * Sets up biometric authentication for a user who is already logged in
   *
   * @returns Observable that resolves when setup is complete
   */
  setupBiometricLogin(): Observable<boolean> {
    // Check if user is already authenticated by checking the currentUserSig
    const currentUser = this.authService.currentUserSig();

    if (!currentUser) {
      console.error('User must be authenticated to set up biometric login');
      return throwError(() => new Error('User must be authenticated to set up biometric login'));
    }

    const username = currentUser.username;
    // Use email as the userId since the IUser interface doesn't have an id field
    const userId = currentUser.email;

    if (!username) {
      console.error('Missing username required for biometric setup');
      return throwError(() => new Error('Missing username for biometric setup'));
    }

    // Register the biometric credential
    return this.registerBiometricCredential(username, userId).pipe(
      tap(success => {
        if (success) {
          this.setBiometricEnabled(true);
          console.log('Biometric login setup completed successfully');
        }
      })
    );
  }
}
