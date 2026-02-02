/**
 * ThreatBadge - Severity indicator badge
 *
 * Features:
 * - Color-coded by threat level
 * - Optional pulse animation for critical threats
 * - Multiple sizes
 */

import { AlertTriangle, AlertCircle, Info, CheckCircle, Skull } from 'lucide-react';

export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'clean';

interface ThreatBadgeProps {
  level: ThreatLevel;
  /** Show the label text */
  showLabel?: boolean;
  /** Show icon */
  showIcon?: boolean;
  /** Size variant */
  size?: 'sm' | 'md' | 'lg';
  /** Enable pulse animation for critical */
  pulse?: boolean;
  className?: string;
}

const levelConfig: Record<
  ThreatLevel,
  { label: string; color: string; bgColor: string; icon: React.ReactNode }
> = {
  critical: {
    label: 'CRITICAL',
    color: 'text-blood',
    bgColor: 'bg-blood/20',
    icon: <Skull className="h-3.5 w-3.5" />,
  },
  high: {
    label: 'HIGH',
    color: 'text-signal',
    bgColor: 'bg-signal/20',
    icon: <AlertTriangle className="h-3.5 w-3.5" />,
  },
  medium: {
    label: 'MEDIUM',
    color: 'text-amber',
    bgColor: 'bg-amber/20',
    icon: <AlertCircle className="h-3.5 w-3.5" />,
  },
  low: {
    label: 'LOW',
    color: 'text-phosphor',
    bgColor: 'bg-phosphor/20',
    icon: <Info className="h-3.5 w-3.5" />,
  },
  info: {
    label: 'INFO',
    color: 'text-radar',
    bgColor: 'bg-radar/20',
    icon: <Info className="h-3.5 w-3.5" />,
  },
  clean: {
    label: 'CLEAN',
    color: 'text-phosphor',
    bgColor: 'bg-phosphor/20',
    icon: <CheckCircle className="h-3.5 w-3.5" />,
  },
};

const sizeStyles = {
  sm: 'px-1.5 py-0.5 text-[10px]',
  md: 'px-2 py-1 text-xs',
  lg: 'px-3 py-1.5 text-sm',
};

export function ThreatBadge({
  level,
  showLabel = true,
  showIcon = true,
  size = 'md',
  pulse = true,
  className = '',
}: ThreatBadgeProps) {
  const config = levelConfig[level];
  const shouldPulse = pulse && level === 'critical';

  return (
    <span
      className={`
        inline-flex items-center gap-1.5
        font-mono font-medium uppercase tracking-wider
        border
        ${config.color} ${config.bgColor} border-current
        ${sizeStyles[size]}
        ${shouldPulse ? 'animate-pulse' : ''}
        ${className}
      `}
    >
      {showIcon && config.icon}
      {showLabel && config.label}
    </span>
  );
}
