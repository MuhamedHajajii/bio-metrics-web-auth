/**
 * @fileoverview Authentication feature routes configuration.
 *
 * Defines all routes related to authentication workflows.
 */

import { Routes } from '@angular/router';
import { LoginComponent } from './pages/login/login.component';
import { RegisterComponent } from './pages/register/register.component';
import { ResetPasswordComponent } from './pages/reset-password/reset-password.component';
import { ProfileComponent } from './pages/profile/profile.component';
import { authGuard } from './guards/auth.guard';

/**
 * Authentication feature routes
 */
export const AUTH_ROUTES: Routes = [
  {
    path: 'login',
    component: LoginComponent,
    title: 'Sign In'
  },
  {
    path: 'register',
    component: RegisterComponent,
    title: 'Create Account'
  },
  {
    path: 'reset-password',
    component: ResetPasswordComponent,
    title: 'Reset Password'
  },
  {
    path: 'profile',
    component: ProfileComponent,
    canActivate: [authGuard],
    title: 'Your Profile'
  },
  {
    path: '',
    redirectTo: 'login',
    pathMatch: 'full'
  }
];
