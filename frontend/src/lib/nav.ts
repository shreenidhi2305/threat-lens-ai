import type { ComponentType } from 'react';

import {
  BellIcon,
  ChartIcon,
  FileScanIcon,
  GridIcon,
  RadarIcon,
  UploadIcon,
  UserIcon,
} from '../ui/icons';
import type { UserRole } from './types';

export interface NavItem {
  to: string;
  label: string;
  icon: ComponentType<{ className?: string }>;
  roles: UserRole[] | 'all';
}

export const NAV_SECTIONS: { heading: string; items: NavItem[] }[] = [
  {
    heading: 'Analysis',
    items: [
      { to: '/dashboard', label: 'Overview', icon: GridIcon, roles: 'all' },
      {
        to: '/submit',
        label: 'Submit File',
        icon: UploadIcon,
        roles: ['Security Analyst', 'Administrator', 'Researcher'],
      },
      {
        to: '/reports',
        label: 'Reports',
        icon: FileScanIcon,
        roles: ['Security Analyst', 'Administrator', 'Researcher'],
      },
    ],
  },
  {
    heading: 'Monitoring',
    items: [
      {
        to: '/threats',
        label: 'Threat Monitor',
        icon: RadarIcon,
        roles: ['Security Analyst', 'SOC Team Member', 'Administrator'],
      },
      {
        to: '/alerts',
        label: 'Alerts',
        icon: BellIcon,
        roles: ['Security Analyst', 'SOC Team Member', 'Administrator'],
      },
      { to: '/analytics', label: 'Analytics', icon: ChartIcon, roles: 'all' },
    ],
  },
  {
    heading: 'Account',
    items: [{ to: '/profile', label: 'Profile', icon: UserIcon, roles: 'all' }],
  },
];

export const canSee = (item: NavItem, role: UserRole | undefined): boolean =>
  item.roles === 'all' || (role !== undefined && item.roles.includes(role));

export const visibleSections = (role: UserRole | undefined) =>
  NAV_SECTIONS.map((s) => ({ ...s, items: s.items.filter((i) => canSee(i, role)) })).filter(
    (s) => s.items.length > 0,
  );
