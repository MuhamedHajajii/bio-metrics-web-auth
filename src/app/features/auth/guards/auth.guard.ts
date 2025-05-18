/**
 * @fileoverview Authentication guard implementation.
 *
 * Guards routes that require authenticated users.
 */

import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { map, take } from 'rxjs/operators';
import { AuthService } from '../services/auth.service';
import { BiometricAuthService } from '../services/biometric-auth.service';

/**
 * Authentication guard function.
 * Protects routes from unauthorized access.
 *
 * @returns A boolean or a promise/observable resolving to a boolean indicating if navigation is allowed
 */
export const authGuard: CanActivateFn = () => {
  const authService = inject(AuthService);
  const biometricAuthService = inject(BiometricAuthService);
  const router = inject(Router);

  console.log('Auth guard activated, checking authentication...');

  // First check if user has a valid biometric token
  if (biometricAuthService.hasBiometricToken()) {
    console.log('Auth guard: Valid biometric token found');
    // Ensure the user is authenticated with the token
    if (!biometricAuthService.loginWithStoredToken()) {
      console.log('Auth guard: Could not authenticate with biometric token');
    } else {
      console.log('Auth guard: Successfully authenticated with biometric token');
      return true;
    }
  }

  // Fall back to Firebase authentication check
  return authService.user$.pipe(
    take(1),
    map(user => {
      const isAuthenticated = !!user;
      console.log('Auth guard: Firebase authentication check result:', isAuthenticated);

      if (!isAuthenticated) {
        // Redirect to login if not authenticated
        console.log('Auth guard: User not authenticated, redirecting to login');
        router.navigate(['/auth/login']);
        return false;
      }
      return true;
    })
  );
};
