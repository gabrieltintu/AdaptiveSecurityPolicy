import { ActivatedRouteSnapshot, CanActivateFn, RouterStateSnapshot } from '@angular/router';
import { createAuthGuard, type AuthGuardData } from 'keycloak-angular';

const isLoggedIn = async (
  _route: ActivatedRouteSnapshot,
  _state: RouterStateSnapshot,
  { authenticated, keycloak }: AuthGuardData,
): Promise<boolean> => {
  if (!authenticated) {
    await keycloak.login();
    return false;
  }
  return true;
};

export const authGuard = createAuthGuard<CanActivateFn>(isLoggedIn);
