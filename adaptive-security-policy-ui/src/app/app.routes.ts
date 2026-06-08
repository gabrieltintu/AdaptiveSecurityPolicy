import { Routes } from '@angular/router';
import { DashboardComponent }  from './pages/dashboard/dashboard';
import { MonitoringComponent } from './pages/monitoring/monitoring';
import { HistoryComponent }    from './pages/history/history';
import { FirewallComponent }   from './pages/firewall/firewall';
import { PolicyComponent }     from './pages/policy/policy';
import { authGuard } from './guards/auth.guard';
import { adminGuard } from './guards/admin.guard';

export const routes: Routes = [
  { path: '',           redirectTo: 'dashboard', pathMatch: 'full' },
  { path: 'dashboard',  component: DashboardComponent,  canActivate: [authGuard] },
  { path: 'monitoring', component: MonitoringComponent, canActivate: [authGuard] },
  { path: 'history',    component: HistoryComponent,    canActivate: [adminGuard] },
  { path: 'firewall',   component: FirewallComponent,   canActivate: [adminGuard] },
  { path: 'policy',     component: PolicyComponent,     canActivate: [adminGuard] },
  { path: 'analytics',  canActivate: [authGuard], loadComponent: () => import('./pages/analytics/analytics').then(m => m.AnalyticsComponent) },
];
