/**
 * @fileoverview Biometric authentication service implementation.
 *
 * Handles biometric authentication and token management.
 */
import { Injectable, PLATFORM_ID, inject } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, of, throwError } from 'rxjs';
import { delay, tap } from 'rxjs/operators';
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
  private platformId = inject(PLATFORM_ID);

  /**
   * Determines if the current device supports biometric authentication
   *
   * @returns True if biometric authentication is supported
   */
  isBiometricSupported(): boolean {
    // Simulate biometric support for all devices for testing purposes
    // In a real app, we would check the actual device capabilities
    return true;

    // Real implementation would check:
    // const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    // return isMobile && (typeof window !== 'undefined' && window.PublicKeyCredential !== undefined);
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
    // For simulation, we'll generate a token with a future expiration
    if (this.isBiometricSupported()) {
      // Simulate biometric authentication delay
      return of(true).pipe(
        delay(1500),
        tap(() => {
          // Generate a mock token with a 7-day expiration
          const mockUsername = `User${Math.floor(Math.random() * 1000)}`;
          const mockEmail = `user${Math.floor(Math.random() * 1000)}@example.com`;
          const userId = `user_${Math.random().toString(36).substring(2, 10)}`;

          const token: AuthToken = {
            token: 'biometric_auth_' + Math.random().toString(36).substring(2, 15),
            expiresAt: Date.now() + (7 * 24 * 60 * 60 * 1000), // 7 days
            userId: userId,
            email: mockEmail,
            username: mockUsername
          };

          // Store the token with all user info
          this.storeToken(token);

          // Update authentication state in AuthService
          this.authService.setAuthenticatedUserFromToken(token.userId, token.email, token.username);

          console.log('Biometric auth successful, token stored:', token);
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
   * Clears any stored biometric tokens
   */
  clearBiometricToken(): void {
    localStorage.removeItem(this.TOKEN_KEY);
    console.log('Biometric token cleared');
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
