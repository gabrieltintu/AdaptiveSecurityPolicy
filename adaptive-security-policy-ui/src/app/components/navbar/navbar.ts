import { Component, inject } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';
import Keycloak from 'keycloak-js';
import { IconComponent } from '../icon/icon';

@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [RouterLink, RouterLinkActive, IconComponent],
  templateUrl: './navbar.html',
  styleUrl: './navbar.css'
})
export class NavbarComponent {
  private readonly keycloak = inject(Keycloak);

  readonly isAdmin = this.keycloak.hasRealmRole('ADMIN');
  readonly username =
    (this.keycloak.tokenParsed as { preferred_username?: string } | undefined)?.preferred_username ?? '';

  logout(): void {
    this.keycloak.logout({ redirectUri: window.location.origin });
  }
}
