import { Routes } from '@angular/router';
import { DashboardComponent }  from './pages/dashboard/dashboard';
import { MonitoringComponent } from './pages/monitoring/monitoring';
import { FirewallComponent }   from './pages/firewall/firewall';
import { authGuard } from './guards/auth.guard';

export const routes: Routes = [
  { path: '',           redirectTo: 'dashboard', pathMatch: 'full' },
  { path: 'dashboard',  component: DashboardComponent,  canActivate: [authGuard] },
  { path: 'monitoring', component: MonitoringComponent, canActivate: [authGuard] },
  { path: 'firewall',   component: FirewallComponent,   canActivate: [authGuard] },
];
