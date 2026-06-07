import { inject } from '@angular/core';
import { ActivatedRouteSnapshot, CanActivateFn, Router, RouterStateSnapshot, UrlTree } from '@angular/router';
import { createAuthGuard, type AuthGuardData } from 'keycloak-angular';

const isAdmin = async (
  _route: ActivatedRouteSnapshot,
  _state: RouterStateSnapshot,
  { authenticated, grantedRoles, keycloak }: AuthGuardData,
): Promise<boolean | UrlTree> => {
  const router = inject(Router);
  if (!authenticated) {
    await keycloak.login();
    return false;
  }
  return grantedRoles.realmRoles.includes('ADMIN') ? true : router.parseUrl('/dashboard');
};

export const adminGuard = createAuthGuard<CanActivateFn>(isAdmin);
