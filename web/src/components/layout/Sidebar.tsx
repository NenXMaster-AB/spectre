/**
 * Sidebar - Navigation with folder-tab styling
 *
 * Features:
 * - Folder-tab styled navigation items
 * - Phosphor green active states
 * - Icon + label navigation
 * - Collapsible sections
 */

import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Search,
  Database,
  Users,
  FileText,
  Plug,
  Settings,
  Shield,
  Activity,
} from 'lucide-react';

interface NavItem {
  to: string;
  icon: React.ReactNode;
  label: string;
  badge?: number;
}

const mainNavItems: NavItem[] = [
  {
    to: '/',
    icon: <LayoutDashboard className="h-5 w-5" />,
    label: 'Command Center',
  },
  {
    to: '/investigations',
    icon: <Search className="h-5 w-5" />,
    label: 'Investigations',
  },
  {
    to: '/entities',
    icon: <Database className="h-5 w-5" />,
    label: 'Entity Database',
  },
  {
    to: '/threat-actors',
    icon: <Users className="h-5 w-5" />,
    label: 'Threat Actors',
  },
  {
    to: '/reports',
    icon: <FileText className="h-5 w-5" />,
    label: 'Intelligence Reports',
  },
];

const systemNavItems: NavItem[] = [
  {
    to: '/plugins',
    icon: <Plug className="h-5 w-5" />,
    label: 'Plugins',
  },
  {
    to: '/settings',
    icon: <Settings className="h-5 w-5" />,
    label: 'Settings',
  },
];

export function Sidebar() {
  return (
    <aside className="w-64 bg-bunker border-r border-steel flex flex-col">
      {/* Main Navigation */}
      <nav className="flex-1 py-4">
        <div className="px-4 mb-2">
          <span className="text-xs font-mono text-concrete uppercase tracking-wider">
            Operations
          </span>
        </div>

        <ul className="space-y-1 px-2">
          {mainNavItems.map((item) => (
            <li key={item.to}>
              <NavLink
                to={item.to}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-4 py-2.5 text-sm font-mono transition-all duration-200
                  ${
                    isActive
                      ? 'bg-slate text-phosphor border-l-2 border-phosphor glow-phosphor-subtle'
                      : 'text-concrete hover:text-paper hover:bg-slate/50 border-l-2 border-transparent'
                  }`
                }
              >
                {item.icon}
                <span>{item.label}</span>
                {item.badge && (
                  <span className="ml-auto bg-blood text-paper text-xs px-1.5 py-0.5 font-mono">
                    {item.badge}
                  </span>
                )}
              </NavLink>
            </li>
          ))}
        </ul>

        {/* System Section */}
        <div className="px-4 mt-8 mb-2">
          <span className="text-xs font-mono text-concrete uppercase tracking-wider">
            System
          </span>
        </div>

        <ul className="space-y-1 px-2">
          {systemNavItems.map((item) => (
            <li key={item.to}>
              <NavLink
                to={item.to}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-4 py-2.5 text-sm font-mono transition-all duration-200
                  ${
                    isActive
                      ? 'bg-slate text-phosphor border-l-2 border-phosphor glow-phosphor-subtle'
                      : 'text-concrete hover:text-paper hover:bg-slate/50 border-l-2 border-transparent'
                  }`
                }
              >
                {item.icon}
                <span>{item.label}</span>
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>

      {/* Footer - System Status */}
      <div className="p-4 border-t border-steel">
        <div className="flex items-center gap-3 text-xs font-mono">
          <Shield className="h-4 w-4 text-phosphor" />
          <div className="flex flex-col">
            <span className="text-concrete">Security Level</span>
            <span className="text-amber">CLASSIFIED</span>
          </div>
        </div>
        <div className="flex items-center gap-3 text-xs font-mono mt-3">
          <Activity className="h-4 w-4 text-phosphor animate-pulse" />
          <div className="flex flex-col">
            <span className="text-concrete">Active Monitors</span>
            <span className="text-phosphor">3 WATCHERS</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
