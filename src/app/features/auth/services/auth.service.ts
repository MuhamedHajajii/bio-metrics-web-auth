/**
 * @fileoverview Authentication service implementation.
 *
 * Handles user authentication, registration, and profile management.
 */

import { HttpClient } from '@angular/common/http';
import { inject, Injectable, signal } from '@angular/core';
import { Auth, createUserWithEmailAndPassword, updateProfile, user } from '@angular/fire/auth';
import { IUser } from '../interfaces/IUser';
import { Observable, from, tap, of, throwError, BehaviorSubject } from 'rxjs';
import { signInWithEmailAndPassword, signOut, User, updatePassword } from 'firebase/auth';

/**
 * AuthService
 *
 * Provides authentication functionality including login, registration,
 * profile updates, and auth state management.
 */
@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly fire = inject(Auth);

  /**
   * Observable of the current authenticated Firebase user
   */
  user$ = user(this.fire);

  /**
   * Signal for the current user with application-specific data
   * @signal
   */
  currentUserSig = signal<IUser | null | undefined>(undefined);

  /**
   * BehaviorSubject to track biometric authentication state
   * This allows us to authenticate without Firebase credentials
   */
  private biometricUser = new BehaviorSubject<IUser | null>(null);

  /**
   * Combined observable that merges Firebase and biometric authentication
   */
  get authenticatedUser$(): Observable<IUser | null> {
    return this.biometricUser.asObservable();
  }

  constructor() {
    // Subscribe to Firebase auth changes to update biometricUser
    this.user$.subscribe(firebaseUser => {
      if (firebaseUser) {
        this.biometricUser.next({
          email: firebaseUser.email || '',
          username: firebaseUser.displayName || ''
        });
      }
    });
  }

  /**
   * Registers a new user with email and password.
   * Also updates the user's display name.
   *
   * @param username The username to set as display name
   * @param email The user's email address
   * @param password The user's password
   * @returns An Observable of the registration process
   */
  register(username: string, email: string, password: string): Observable<void> {
    const promise = createUserWithEmailAndPassword(this.fire, email, password)
      .then(response => {
        // Update the user profile with the username
        return updateProfile(response.user, { displayName: username });
      });

    return from(promise);
  }

  /**
   * Logs in a user with email and password.
   *
   * @param email The user's email address
   * @param password The user's password
   * @returns An Observable of the login process
   */
  login(email: string, password: string): Observable<void> {
    const promise = signInWithEmailAndPassword(this.fire, email, password)
      .then(() => {
        // Successful login
      });

    return from(promise).pipe(
      tap(() => {
        // Update the current user signal when logged in
        this.user$.subscribe(firebaseUser => {
          if (firebaseUser) {
            this.currentUserSig.set({
              email: firebaseUser.email!,
              username: firebaseUser.displayName!
            });

            // Also update the biometric user
            this.biometricUser.next({
              email: firebaseUser.email!,
              username: firebaseUser.displayName!
            });
          }
        });
      })
    );
  }

  /**
   * Sets the authenticated user from a token (for biometric auth)
   *
   * @param userId The user ID from the token
   */
  setAuthenticatedUserFromToken(userId: string): void {
    // In a real app, we would validate the token with the server
    // and get the actual user data. For this demo, we'll create a mock user.
    const mockUser: IUser = {
      email: `${userId}@example.com`,
      username: `User ${userId.slice(-4)}`
    };

    this.currentUserSig.set(mockUser);
    this.biometricUser.next(mockUser);
  }

  /**
   * Updates the user's profile information.
   *
   * @param username The new username to set
   * @returns An Observable of the update process
   */
  updateProfile(username: string): Observable<void> {
    const currentUser = this.fire.currentUser;

    if (!currentUser) {
      return throwError(() => new Error('No authenticated user found'));
    }

    const promise = updateProfile(currentUser, { displayName: username })
      .then(() => {
        // Update the current user signal
        if (this.currentUserSig()) {
          this.currentUserSig.update(user => {
            if (user) {
              return { ...user, username };
            }
            return user;
          });
        }
      });

    return from(promise);
  }

  /**
   * Updates the user's password.
   *
   * @param newPassword The new password to set
   * @returns An Observable of the password update process
   */
  updatePassword(newPassword: string): Observable<void> {
    const currentUser = this.fire.currentUser;

    if (!currentUser) {
      return throwError(() => new Error('No authenticated user found'));
    }

    const promise = updatePassword(currentUser, newPassword);
    return from(promise);
  }

  /**
   * Logs out the current user.
   */
  logout(): void {
    signOut(this.fire).then(() => {
      // Reset current user signal when logged out
      this.currentUserSig.set(null);
      this.biometricUser.next(null);
    });
  }
}
