/**
 * InvestigationTimeline - Event timeline display
 *
 * Features:
 * - Chronological event display
 * - Color-coded by event type
 * - Auto-scroll to latest
 */

import { useRef, useEffect } from 'react';
import {
  Play,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Zap,
  Network,
  FileText,
  Target,
  Clock,
} from 'lucide-react';
import type { InvestigationEvent } from '../../types';

interface InvestigationTimelineProps {
  events: InvestigationEvent[];
  autoScroll?: boolean;
  maxHeight?: string;
  className?: string;
}

const eventConfig: Record<
  string,
  { icon: typeof Play; color: string; label: string }
> = {
  'investigation.started': {
    icon: Play,
    color: 'text-phosphor',
    label: 'Investigation started',
  },
  'investigation.completed': {
    icon: CheckCircle,
    color: 'text-phosphor',
    label: 'Investigation completed',
  },
  'investigation.failed': {
    icon: XCircle,
    color: 'text-blood',
    label: 'Investigation failed',
  },
  'investigation.cancelled': {
    icon: AlertTriangle,
    color: 'text-signal',
    label: 'Investigation cancelled',
  },
  'stage.changed': {
    icon: Target,
    color: 'text-amber',
    label: 'Stage changed',
  },
  'plan.created': {
    icon: FileText,
    color: 'text-radar',
    label: 'Plan created',
  },
  'plugin.started': {
    icon: Zap,
    color: 'text-concrete',
    label: 'Plugin started',
  },
  'plugin.completed': {
    icon: CheckCircle,
    color: 'text-phosphor',
    label: 'Plugin completed',
  },
  'plugin.failed': {
    icon: XCircle,
    color: 'text-signal',
    label: 'Plugin failed',
  },
  'finding.discovered': {
    icon: FileText,
    color: 'text-amber',
    label: 'Finding discovered',
  },
  'entity.discovered': {
    icon: Network,
    color: 'text-radar',
    label: 'Entity discovered',
  },
  'threat.detected': {
    icon: AlertTriangle,
    color: 'text-blood',
    label: 'Threat detected',
  },
  'progress.updated': {
    icon: Clock,
    color: 'text-concrete',
    label: 'Progress updated',
  },
};

function formatTimestamp(isoString: string): string {
  const date = new Date(isoString);
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

function getEventDescription(event: InvestigationEvent): string {
  const { type, data } = event;

  switch (type) {
    case 'stage.changed':
      return `Entered ${(data.stage as string)?.toUpperCase() || 'unknown'} stage`;
    case 'plan.created':
      return `${(data.plugins as string[])?.length || 0} plugins scheduled`;
    case 'plugin.started':
    case 'plugin.completed':
    case 'plugin.failed':
      return data.plugin as string || 'Unknown plugin';
    case 'finding.discovered':
      return `${(data.finding as { type?: string })?.type || 'Finding'} from ${(data.finding as { source?: string })?.source || 'unknown'}`;
    case 'entity.discovered':
      return `${(data.entity as { type?: string })?.type}: ${(data.entity as { value?: string })?.value || 'unknown'}`;
    case 'threat.detected':
      return `Threat level: ${(data.threat_level as string)?.toUpperCase() || 'UNKNOWN'}`;
    case 'investigation.failed':
      return data.error as string || 'Unknown error';
    default:
      return '';
  }
}

export function InvestigationTimeline({
  events,
  autoScroll = true,
  maxHeight = '400px',
  className = '',
}: InvestigationTimelineProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [events, autoScroll]);

  if (events.length === 0) {
    return (
      <div className={`text-center py-8 text-concrete font-mono text-sm ${className}`}>
        No events yet
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className={`overflow-y-auto ${className}`}
      style={{ maxHeight }}
    >
      <div className="relative">
        {/* Timeline line */}
        <div className="absolute left-4 top-0 bottom-0 w-px bg-steel" />

        {/* Events */}
        <div className="space-y-0">
          {events.map((event, index) => {
            const config = eventConfig[event.type] || {
              icon: Clock,
              color: 'text-concrete',
              label: event.type,
            };
            const Icon = config.icon;
            const description = getEventDescription(event);
            const isLast = index === events.length - 1;

            return (
              <div
                key={event.id}
                className={`
                  relative flex items-start gap-4 py-3 px-2
                  ${isLast ? 'bg-void/50' : ''}
                `}
              >
                {/* Timeline dot */}
                <div
                  className={`
                    relative z-10 flex items-center justify-center
                    w-8 h-8 rounded-full bg-bunker border border-steel
                    ${isLast ? 'border-phosphor box-glow-phosphor' : ''}
                  `}
                >
                  <Icon className={`h-4 w-4 ${config.color}`} />
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0 pt-1">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className={`font-mono text-sm ${config.color}`}>
                      {config.label}
                    </span>
                    <span className="text-[10px] font-mono text-steel">
                      {formatTimestamp(event.timestamp)}
                    </span>
                  </div>
                  {description && (
                    <p className="text-xs font-mono text-concrete truncate">
                      {description}
                    </p>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
