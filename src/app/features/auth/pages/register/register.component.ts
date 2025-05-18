/**
 * @fileoverview Registration component implementation.
 *
 * This component handles user registration with email and password.
 */
import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, Validators } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { NavigationService } from '../../services/navigation.service';

/**
 * RegisterComponent
 *
 * Provides a form for new users to create an account.
 *
 * @example
 * <app-register></app-register>
 */
@Component({
  selector: 'app-register',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule],
  templateUrl: './register.component.html',
  styleUrl: './register.component.scss'
})
export class RegisterComponent {
  private fb = inject(FormBuilder);
  private authService = inject(AuthService);
  private navigationService = inject(NavigationService);

  /**
   * Signal to indicate if registration is being processed.
   * @signal
   */
  protected readonly isLoading = signal<boolean>(false);

  /**
   * Signal to store error messages.
   * @signal
   */
  protected readonly errorMessage = signal<string | null>(null);

  /**
   * The registration form with validation.
   */
  protected registerForm = this.fb.group({
    username: ['', [Validators.required, Validators.minLength(3)]],
    email: ['', [Validators.required, Validators.email]],
    password: ['', [Validators.required, Validators.minLength(6)]],
    confirmPassword: ['', [Validators.required]]
  }, {
    validators: this.passwordMatchValidator
  });

  /**
   * Validates that password and confirmPassword fields match.
   *
   * @param formGroup The form group to validate
   * @returns An object with the validation error or null if valid
   */
  private passwordMatchValidator(formGroup: any): { [key: string]: boolean } | null {
    const password = formGroup.get('password');
    const confirmPassword = formGroup.get('confirmPassword');

    if (password.value !== confirmPassword.value) {
      confirmPassword.setErrors({ passwordMismatch: true });
      return { passwordMismatch: true };
    } else {
      return null;
    }
  }

  /**
   * Handles the registration form submission.
   */
  onSubmit(): void {
    if (this.registerForm.invalid) {
      return;
    }

    this.isLoading.set(true);
    this.errorMessage.set(null);

    const username = this.registerForm.get('username')?.value;
    const email = this.registerForm.get('email')?.value;
    const password = this.registerForm.get('password')?.value;

    if (!username || !email || !password) {
      this.errorMessage.set('All fields are required');
      this.isLoading.set(false);
      return;
    }

    this.authService.register(username, email, password).subscribe({
      next: () => {
        this.isLoading.set(false);
        this.navigationService.navigateToHome();
      },
      error: (error) => {
        console.error('Registration error:', error);
        this.errorMessage.set('Registration failed. Please try again with a different email.');
        this.isLoading.set(false);
      }
    });
  }

  /**
   * Navigates to the login page.
   */
  goToLogin(): void {
    this.navigationService.navigateToLogin();
  }
}
