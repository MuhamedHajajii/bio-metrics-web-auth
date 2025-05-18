/**
 * @fileoverview Application routes configuration.
 *
 * Defines the main application routes and lazy-loaded feature modules.
 */

import { Routes } from '@angular/router';
import { authGuard } from './features/auth/guards/auth.guard';
import { HomeComponent } from './features/home/home.component';

/**
 * Main application routes
 */
export const routes: Routes = [
  {
    path: 'auth',
    loadChildren: () => import('./features/auth/auth.routes').then(m => m.AUTH_ROUTES)
  },
  {
    path: 'home',
    component: HomeComponent,
    canActivate: [authGuard],
    title: 'Dashboard'
  },
  {
    path: '',
    redirectTo: 'auth/login',
    pathMatch: 'full'
  },
  {
    path: '**',
    redirectTo: 'auth/login'
  }
];
