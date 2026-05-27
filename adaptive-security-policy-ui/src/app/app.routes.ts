import { Routes } from '@angular/router';
import { DashboardComponent }  from './pages/dashboard/dashboard';
import { MonitoringComponent } from './pages/monitoring/monitoring';
import { FirewallComponent }   from './pages/firewall/firewall';

export const routes: Routes = [
  { path: '',            redirectTo: 'dashboard', pathMatch: 'full' },
  { path: 'dashboard',  component: DashboardComponent },
  { path: 'monitoring', component: MonitoringComponent },
  { path: 'firewall',   component: FirewallComponent },
];
