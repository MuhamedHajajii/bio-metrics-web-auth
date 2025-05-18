/**
 * @fileoverview User profile component implementation.
 *
 * This component displays the user's profile information and allows editing.
 */
import { Component, inject, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, Validators, FormGroup } from '@angular/forms';
import { AuthService } from '../../services/auth.service';
import { Router, RouterModule } from '@angular/router';
import { IUser } from '../../interfaces/IUser';
import { NavigationService } from '../../services/navigation.service';

/**
 * ProfileComponent
 *
 * Displays user profile information and allows editing profile details.
 *
 * @example
 * <app-profile></app-profile>
 */
@Component({
  selector: 'app-profile',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule],
  templateUrl: './profile.component.html',
  styleUrl: './profile.component.scss'
})
export class ProfileComponent implements OnInit {
  private authService = inject(AuthService);
  private fb = inject(FormBuilder);
  private router = inject(Router);
  private navigationService = inject(NavigationService);

  /**
   * Signal to indicate if profile data is being loaded.
   * @signal
   */
  protected readonly isLoading = signal<boolean>(true);

  /**
   * Signal to indicate if profile is being updated.
   * @signal
   */
  protected readonly isSaving = signal<boolean>(false);

  /**
   * Signal to store any error message.
   * @signal
   */
  protected readonly errorMessage = signal<string | null>(null);

  /**
   * Signal to store success message after updates.
   * @signal
   */
  protected readonly successMessage = signal<string | null>(null);

  /**
   * Signal to store the user profile data.
   * @signal
   */
  protected readonly user = signal<IUser | null>(null);

  /**
   * Profile edit form.
   */
  protected profileForm!: FormGroup;

  /**
   * Initializes the component and loads the user profile.
   */
  ngOnInit(): void {
    this.initForm();
    this.loadUserProfile();
  }

  /**
   * Initializes the profile edit form.
   */
  private initForm(): void {
    this.profileForm = this.fb.group({
      username: ['', [Validators.required, Validators.minLength(3)]],
      email: [{value: '', disabled: true}],
    });
  }

  /**
   * Loads the user profile data from the auth service.
   */
  private loadUserProfile(): void {
    this.isLoading.set(true);
    this.authService.user$.subscribe({
      next: (user) => {
        if (user) {
          const userData = {
            email: user.email || '',
            username: user.displayName || ''
          };
          this.user.set(userData);
          this.profileForm.patchValue({
            username: userData.username,
            email: userData.email
          });
        } else {
          // No user is logged in, redirect to login
          this.navigationService.navigateToLogin();
        }
        this.isLoading.set(false);
      },
      error: (error) => {
        console.error('Error loading user profile:', error);
        this.errorMessage.set('Error loading user profile. Please try again.');
        this.isLoading.set(false);
      }
    });
  }

  /**
   * Handles form submission for updating profile.
   */
  onSubmit(): void {
    if (this.profileForm.invalid) {
      return;
    }

    this.isSaving.set(true);
    this.errorMessage.set(null);
    this.successMessage.set(null);

    const updatedUsername = this.profileForm.get('username')?.value;

    this.authService.updateProfile(updatedUsername).subscribe({
      next: () => {
        this.successMessage.set('Profile updated successfully!');
        this.isSaving.set(false);
        if (this.user()) {
          const updatedUser = {
            ...this.user()!,
            username: updatedUsername
          };
          this.user.set(updatedUser);
        }
      },
      error: (error) => {
        console.error('Error updating profile:', error);
        this.errorMessage.set('Error updating profile. Please try again.');
        this.isSaving.set(false);
      }
    });
  }

  /**
   * Logs the user out and redirects to login page.
   */
  logout(): void {
    this.authService.logout();
    this.navigationService.navigateToLogin();
  }
}
