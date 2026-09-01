import type { UserRole } from './types';

export interface NavItem {
  to: string;
  label: string;
  roles: UserRole[] | 'all';
}

export const NAV_ITEMS: NavItem[] = [
  { to: '/dashboard', label: 'Dashboard', roles: 'all' },
  { to: '/upload', label: 'Submit File', roles: ['Security Analyst', 'Administrator', 'Researcher'] },
  { to: '/analysis', label: 'Analysis Report', roles: ['Security Analyst', 'Administrator', 'Researcher'] },
  { to: '/malware-report', label: 'Malware Report', roles: ['Security Analyst', 'Administrator', 'Researcher'] },
  {
    to: '/threat-monitoring',
    label: 'Threat Monitoring',
    roles: ['Security Analyst', 'SOC Team Member', 'Administrator'],
  },
  { to: '/alerts', label: 'Alerts', roles: ['Security Analyst', 'SOC Team Member', 'Administrator'] },
  { to: '/analytics', label: 'Analytics', roles: 'all' },
  { to: '/profile', label: 'Profile', roles: 'all' },
];

export const visibleNav = (role: UserRole | undefined): NavItem[] =>
  NAV_ITEMS.filter((item) => item.roles === 'all' || (role && item.roles.includes(role)));
