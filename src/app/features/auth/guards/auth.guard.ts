/**
 * @fileoverview Authentication guard implementation.
 *
 * Guards routes that require authenticated users.
 */

import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { map, take } from 'rxjs/operators';
import { AuthService } from '../services/auth.service';

/**
 * Authentication guard function.
 * Protects routes from unauthorized access.
 *
 * @returns A boolean or a promise/observable resolving to a boolean indicating if navigation is allowed
 */
export const authGuard: CanActivateFn = () => {
  const authService = inject(AuthService);
  const router = inject(Router);

  return authService.user$.pipe(
    take(1),
    map(user => {
      const isAuthenticated = !!user;
      if (!isAuthenticated) {
        // Redirect to login if not authenticated
        router.navigate(['/auth/login']);
        return false;
      }
      return true;
    })
  );
};
