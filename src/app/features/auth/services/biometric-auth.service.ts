/**
 * @fileoverview Biometric authentication service implementation.
 *
 * Handles biometric authentication and token management.
 */
import { Injectable, inject } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, of, throwError } from 'rxjs';
import { delay, tap } from 'rxjs/operators';
import { AuthService } from './auth.service';
import { NavigationService } from './navigation.service';

/**
 * Token interface defining the structure of authentication tokens
 */
interface AuthToken {
  token: string;
  expiresAt: number;
  userId: string;
}

/**
 * BiometricAuthService
 *
 * Manages biometric authentication and token validation for seamless login.
 */
@Injectable({
  providedIn: 'root'
})
export class BiometricAuthService {
  private readonly TOKEN_KEY = 'biometric_auth_token';
  private authService = inject(AuthService);
  private navigationService = inject(NavigationService);
  private router = inject(Router);

  /**
   * Determines if the current device supports biometric authentication
   *
   * @returns True if biometric authentication is supported
   */
  isBiometricSupported(): boolean {
    // Check if the device is mobile
    const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);

    // In a real app, we would also check for Web Authentication API support:
    // return isMobile && (window.PublicKeyCredential !== undefined);

    return isMobile;
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
   * Authenticates the user using biometrics
   *
   * @returns An Observable that resolves to a success value on successful authentication
   */
  authenticateWithBiometrics(): Observable<boolean> {
    // In a real implementation, we would:
    // 1. Request biometric authentication through WebAuthn API
    // 2. Verify the response on our server
    // 3. Receive and store the token

    // For simulation, we'll generate a token with a future expiration
    if (this.isBiometricSupported()) {
      // Simulate biometric authentication delay
      return of(true).pipe(
        delay(1500),
        tap(() => {
          // Generate a mock token with a 7-day expiration
          const token: AuthToken = {
            token: 'biometric_auth_' + Math.random().toString(36).substr(2),
            expiresAt: Date.now() + (7 * 24 * 60 * 60 * 1000), // 7 days
            userId: 'user_' + Math.random().toString(36).substr(2)
          };

          // Store the token
          this.storeToken(token);

          // Update authentication state in AuthService
          this.authService.setAuthenticatedUserFromToken(token.userId);
        })
      );
    } else {
      return throwError(() => new Error('Biometric authentication not supported on this device'));
    }
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
        this.authService.setAuthenticatedUserFromToken(token.userId);
        return true;
      }
    }
    return false;
  }

  /**
   * Clears any stored biometric tokens
   */
  clearBiometricToken(): void {
    localStorage.removeItem(this.TOKEN_KEY);
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
    const tokenJson = localStorage.getItem(this.TOKEN_KEY);
    if (!tokenJson) return null;

    try {
      return JSON.parse(tokenJson) as AuthToken;
    } catch (e) {
      console.error('Error parsing stored token:', e);
      return null;
    }
  }
}
