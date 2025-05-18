/**
 * @fileoverview Footer component implementation.
 *
 * This component provides a consistent footer across the application.
 */

import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';

/**
 * FooterComponent
 *
 * Provides a consistent footer for the application with links and copyright information.
 *
 * @example
 * <app-footer></app-footer>
 */
@Component({
  selector: 'app-footer',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './footer.component.html',
  styleUrl: './footer.component.scss'
})
export class FooterComponent {
  /**
   * Current year for copyright information
   */
  currentYear = new Date().getFullYear();
}
