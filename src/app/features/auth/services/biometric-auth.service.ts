/**
 * @fileoverview Biometric authentication service using WebAuthn API.
 *
 * Handles biometric authentication via fingerprint or Face ID without requiring backend integration.
 */
import { Injectable, PLATFORM_ID, inject } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, of, throwError, from } from 'rxjs';
import { delay, tap, catchError, map } from 'rxjs/operators';
import { AuthService } from './auth.service';
import { NavigationService } from './navigation.service';
import { isPlatformBrowser } from '@angular/common';

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
 * BiometricAuthService
 *
 * Manages biometric authentication using WebAuthn API for seamless fingerprint/Face ID login.
 */
@Injectable({
  providedIn: 'root'
})
export class BiometricAuthService {
  private readonly TOKEN_KEY = 'biometric_auth_token';
  private readonly CREDENTIAL_KEY = 'webauthn_credential_id';
  private authService = inject(AuthService);
  private navigationService = inject(NavigationService);
  private router = inject(Router);
  private platformId = inject(PLATFORM_ID);

  /**
   * Determines if the current device supports biometric authentication through WebAuthn
   *
   * @returns True if biometric authentication is supported
   */
  isBiometricSupported(): boolean {
    if (!isPlatformBrowser(this.platformId)) {
      return false;
    }

    // Check if WebAuthn is available in this browser
    return window.PublicKeyCredential !== undefined;
  }

  /**
   * Checks if a biometric token exists and is valid
   *
   * @returns True if a valid token exists
   */
  hasBiometricToken(): boolean {
    const tokenData = this.getStoredToken();
    if (!tokenData) return false;

    // Check if token is expired
    return tokenData.expiresAt > Date.now();
  }

  /**
   * Registers the user's biometric credential (fingerprint/Face ID)
   *
   * @param username The username to associate with the credential
   * @param userId A unique user identifier
   * @returns An Observable that resolves when registration is complete
   */
  registerBiometricCredential(username: string, userId: string): Observable<boolean> {
    if (!this.isBiometricSupported()) {
      return throwError(() => new Error('WebAuthn is not supported in this browser'));
    }

    // Generate a random challenge
    const challenge = this.generateRandomChallenge();

    // Prepare creation options according to WebAuthn spec
    const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
      challenge: challenge,
      rp: {
        name: "Angular Biometric Auth Demo",
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
        userVerification: "required" // Require biometric verification
      },
      timeout: 60000,
      attestation: "none" // Don't require attestation to simplify
    };

    // Call WebAuthn create() method to register the credential
    return from(navigator.credentials.create({
      publicKey: publicKeyCredentialCreationOptions
    }) as Promise<PublicKeyCredential>).pipe(
      map(credential => {
        // Store the credential ID for later authentication
        const rawId = new Uint8Array(credential.rawId);
        const credentialId = this.bufferToBase64UrlString(rawId);

        // Generate a mock token with the credential ID
        const token: AuthToken = {
          token: 'webauthn_auth_' + Math.random().toString(36).substring(2, 15),
          expiresAt: Date.now() + (30 * 24 * 60 * 60 * 1000), // 30 days
          userId: userId,
          email: `${username}@example.com`, // Mock email
          username: username,
          credentialId: credentialId
        };

        // Store the token and credential ID
        this.storeToken(token);
        localStorage.setItem(this.CREDENTIAL_KEY, credentialId);

        console.log('Biometric credential registered successfully:', credentialId);
        return true;
      }),
      catchError(error => {
        console.error('Error registering credential:', error);
        return throwError(() => new Error('Failed to register biometric credential: ' + error.message));
      })
    );
  }

  /**
   * Authenticates the user using biometrics (fingerprint/Face ID)
   *
   * @returns An Observable that resolves to a success value on successful authentication
   */
  authenticateWithBiometrics(): Observable<boolean> {
    if (!this.isBiometricSupported()) {
      return throwError(() => new Error('WebAuthn is not supported in this browser'));
    }

    // Get stored credential ID if available
    const credentialId = localStorage.getItem(this.CREDENTIAL_KEY);
    if (!credentialId) {
      return throwError(() => new Error('No biometric credential found. Please register first.'));
    }

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

    // Call WebAuthn get() method to authenticate
    return from(navigator.credentials.get({
      publicKey: publicKeyCredentialRequestOptions
    }) as Promise<PublicKeyCredential>).pipe(
      map(assertion => {
        // Authentication succeeded - retrieve and update the stored token
        const token = this.getStoredToken();

        if (token) {
          // Update token expiration
          token.expiresAt = Date.now() + (30 * 24 * 60 * 60 * 1000); // 30 days
          this.storeToken(token);

          // Update authentication state in AuthService
          this.authService.setAuthenticatedUserFromToken(
            token.userId,
            token.email,
            token.username
          );

          console.log('Biometric authentication successful');
          return true;
        } else {
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
    if (this.hasBiometricToken()) {
      const token = this.getStoredToken();
      if (token) {
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
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.CREDENTIAL_KEY);
    console.log('Biometric token and credential cleared');
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
    localStorage.setItem(this.TOKEN_KEY, JSON.stringify(token));
  }

  /**
   * Retrieves the stored authentication token
   *
   * @returns The stored token or null if none exists
   */
  private getStoredToken(): AuthToken | null {
    if(isPlatformBrowser(this.platformId)) {
      const tokenJson = localStorage.getItem(this.TOKEN_KEY);
      if (!tokenJson) return null;

      try {
        return JSON.parse(tokenJson) as AuthToken;
      } catch (e) {
        console.error('Error parsing stored token:', e);
        return null;
      }
    }
    return null;
  }
}
