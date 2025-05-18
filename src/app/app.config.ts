/**
 * @fileoverview Configuration for the Angular application.
 *
 * This file sets up the core providers for the application,
 * including routing, client hydration, HTTP client, animations,
 * and Firebase integration.
 */
import { ApplicationConfig, importProvidersFrom, APP_INITIALIZER } from '@angular/core';
import { provideRouter, withHashLocation } from '@angular/router';

import { routes } from './app.routes';
import { provideClientHydration } from '@angular/platform-browser';
import { provideHttpClient, withFetch } from '@angular/common/http';
import { provideAnimations } from '@angular/platform-browser/animations';

import { initializeApp } from 'firebase/app';
import { environment } from '../environments/environments';
import { getFirestore } from 'firebase/firestore';
import { getAuth } from 'firebase/auth';
import { getStorage } from 'firebase/storage';

import { provideFirebaseApp } from '@angular/fire/app';
import { provideAuth } from '@angular/fire/auth';
import { provideFirestore } from '@angular/fire/firestore';
import { provideStorage } from '@angular/fire/storage';

import { BiometricAuthService } from './features/auth/services/biometric-auth.service';
import { NavigationService } from './features/auth/services/navigation.service';

// Function to check for biometric token on app initialization
export function biometricTokenInitializer(
  biometricAuthService: BiometricAuthService,
  navigationService: NavigationService
) {
  return () => {
    // If there's a valid biometric token, we can perform actions
    // like pre-loading user data or redirecting to the home page
    if (biometricAuthService.hasBiometricToken()) {
      biometricAuthService.loginWithStoredToken();
      return Promise.resolve(true);
    }
    return Promise.resolve(true);
  };
}

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes,withHashLocation()),
    provideClientHydration(),
    provideHttpClient(withFetch()),
    provideAnimations(),
    importProvidersFrom(
      [
        provideFirebaseApp(() => initializeApp(environment.firebaseConfig)),
        provideAuth(() => getAuth()),
        provideFirestore(() => getFirestore()),
        provideStorage(() => getStorage()),
      ]
    ),
    {
      provide: APP_INITIALIZER,
      useFactory: biometricTokenInitializer,
      deps: [BiometricAuthService, NavigationService],
      multi: true
    }
  ]
};
