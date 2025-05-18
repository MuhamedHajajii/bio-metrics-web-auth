/**
 * @fileoverview Authentication layout component implementation.
 *
 * This component provides a consistent layout for authentication pages.
 */

import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';

/**
 * AuthLayoutComponent
 *
 * Provides a consistent layout wrapper for authentication pages like login and register.
 *
 * @example
 * <app-auth-layout>
 *   <app-login></app-login>
 * </app-auth-layout>
 */
@Component({
  selector: 'app-auth-layout',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './auth-layout.component.html',
  styleUrl: './auth-layout.component.scss'
})
export class AuthLayoutComponent {
  // Current year for copyright footer
  currentYear = new Date().getFullYear();
}
