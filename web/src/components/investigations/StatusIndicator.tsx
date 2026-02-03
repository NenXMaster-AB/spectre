/**
 * StatusIndicator - Investigation status display
 *
 * Features:
 * - Animated indicators for active statuses
 * - Color-coded by status type
 * - Optional text label
 */

import { Loader2, CheckCircle, XCircle, AlertCircle, Clock, Zap } from 'lucide-react';
import type { InvestigationStatus } from '../../types';

interface StatusIndicatorProps {
  status: InvestigationStatus;
  showLabel?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const statusConfig: Record<
  InvestigationStatus,
  { label: string; color: string; bgColor: string; Icon: typeof Loader2; animate?: string }
> = {
  pending: {
    label: 'PENDING',
    color: 'text-concrete',
    bgColor: 'bg-concrete/20',
    Icon: Clock,
  },
  planning: {
    label: 'PLANNING',
    color: 'text-amber',
    bgColor: 'bg-amber/20',
    Icon: Loader2,
    animate: 'animate-spin',
  },
  executing: {
    label: 'EXECUTING',
    color: 'text-phosphor',
    bgColor: 'bg-phosphor/20',
    Icon: Zap,
    animate: 'animate-pulse',
  },
  correlating: {
    label: 'CORRELATING',
    color: 'text-radar',
    bgColor: 'bg-radar/20',
    Icon: Loader2,
    animate: 'animate-spin',
  },
  enriching: {
    label: 'ENRICHING',
    color: 'text-amber',
    bgColor: 'bg-amber/20',
    Icon: Loader2,
    animate: 'animate-spin',
  },
  completed: {
    label: 'COMPLETED',
    color: 'text-phosphor',
    bgColor: 'bg-phosphor/20',
    Icon: CheckCircle,
  },
  failed: {
    label: 'FAILED',
    color: 'text-blood',
    bgColor: 'bg-blood/20',
    Icon: XCircle,
  },
  cancelled: {
    label: 'CANCELLED',
    color: 'text-signal',
    bgColor: 'bg-signal/20',
    Icon: AlertCircle,
  },
};

const sizeStyles = {
  sm: { badge: 'px-1.5 py-0.5 text-[10px] gap-1', icon: 'h-3 w-3' },
  md: { badge: 'px-2 py-1 text-xs gap-1.5', icon: 'h-3.5 w-3.5' },
  lg: { badge: 'px-3 py-1.5 text-sm gap-2', icon: 'h-4 w-4' },
};

export function StatusIndicator({
  status,
  showLabel = true,
  size = 'md',
  className = '',
}: StatusIndicatorProps) {
  const config = statusConfig[status];
  const { Icon, animate } = config;
  const styles = sizeStyles[size];

  return (
    <span
      className={`
        inline-flex items-center
        font-mono font-medium uppercase tracking-wider
        border
        ${config.color} ${config.bgColor} border-current
        ${styles.badge}
        ${className}
      `}
    >
      <Icon className={`${styles.icon} ${animate || ''}`} />
      {showLabel && config.label}
    </span>
  );
}
