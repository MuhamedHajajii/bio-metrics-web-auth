/**
 * @fileoverview Reset password component implementation.
 *
 * This component allows users to request a password reset.
 */
import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, Validators } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { NavigationService } from '../../services/navigation.service';

/**
 * ResetPasswordComponent
 *
 * Provides a form for users to request a password reset via email.
 *
 * @example
 * <app-reset-password></app-reset-password>
 */
@Component({
  selector: 'app-reset-password',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule],
  templateUrl: './reset-password.component.html',
  styleUrl: './reset-password.component.scss'
})
export class ResetPasswordComponent {
  private fb = inject(FormBuilder);
  private authService = inject(AuthService);
  private navigationService = inject(NavigationService);

  /**
   * Signal to indicate if a reset password request is being processed.
   * @signal
   */
  protected readonly isLoading = signal<boolean>(false);

  /**
   * Signal to store error messages.
   * @signal
   */
  protected readonly errorMessage = signal<string | null>(null);

  /**
   * Signal to store success messages.
   * @signal
   */
  protected readonly successMessage = signal<string | null>(null);

  /**
   * The reset password form with validation.
   */
  protected resetForm = this.fb.group({
    email: ['', [Validators.required, Validators.email]]
  });

  /**
   * Handles the form submission to request a password reset.
   */
  onSubmit(): void {
    if (this.resetForm.invalid) {
      return;
    }

    this.isLoading.set(true);
    this.errorMessage.set(null);
    this.successMessage.set(null);

    const email = this.resetForm.get('email')?.value;

    // For now, simulate a password reset request
    // In a real implementation, you would call:
    // this.authService.resetPassword(email).subscribe({...})

    setTimeout(() => {
      this.successMessage.set(`Password reset instructions have been sent to ${email}. Please check your email.`);
      this.isLoading.set(false);
      this.resetForm.reset();
    }, 1500);
  }

  /**
   * Navigates back to the login page.
   */
  goToLogin(): void {
    this.navigationService.navigateToLogin();
  }
}
