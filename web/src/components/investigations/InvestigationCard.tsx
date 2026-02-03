/**
 * InvestigationCard - Summary card for investigation lists
 *
 * Features:
 * - Dossier folder-tab style
 * - Status indicator with animation
 * - Threat level badge
 * - Progress bar for active investigations
 */

import { Link } from 'react-router-dom';
import { Clock, FileText, Network, Target } from 'lucide-react';
import { Card } from '../common/Card';
import { ThreatBadge } from '../common/ThreatBadge';
import { Timestamp } from '../common/Timestamp';
import { StatusIndicator } from './StatusIndicator';
import { ProgressBar } from './ProgressBar';
import type { InvestigationSummary, ThreatLevel } from '../../types';
import { isActiveStatus } from '../../hooks';

interface InvestigationCardProps {
  investigation: InvestigationSummary;
  className?: string;
}

export function InvestigationCard({ investigation, className = '' }: InvestigationCardProps) {
  const {
    id,
    query,
    target,
    status,
    progress,
    current_stage,
    threat_level,
    findings_count,
    entities_count,
    created_at,
    duration_seconds,
  } = investigation;

  const isActive = isActiveStatus(status);
  const threatLevel = threat_level as ThreatLevel;

  return (
    <Link to={`/investigations/${id}`} className={`block ${className}`}>
      <Card
        showAccent
        isActive={isActive}
        padding="none"
        className="hover:border-phosphor/50 transition-colors group"
      >
        {/* Header */}
        <div className="px-4 py-3 border-b border-steel flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <Target className="h-4 w-4 text-phosphor flex-shrink-0" />
              <span className="font-mono text-sm text-phosphor truncate">
                {target.value}
              </span>
              <span className="text-xs text-concrete uppercase">
                {target.type}
              </span>
            </div>
            <p className="text-paper text-sm truncate group-hover:text-phosphor transition-colors">
              {query}
            </p>
          </div>
          <StatusIndicator status={status} size="sm" />
        </div>

        {/* Progress (active investigations only) */}
        {isActive && (
          <div className="px-4 py-3 border-b border-steel/50 bg-void/50">
            <ProgressBar
              progress={progress}
              stage={current_stage}
              showPercentage
              size="sm"
            />
          </div>
        )}

        {/* Stats */}
        <div className="px-4 py-3 flex items-center justify-between gap-4">
          <div className="flex items-center gap-4 text-xs font-mono text-concrete">
            <span className="flex items-center gap-1.5">
              <FileText className="h-3.5 w-3.5" />
              {findings_count} findings
            </span>
            <span className="flex items-center gap-1.5">
              <Network className="h-3.5 w-3.5" />
              {entities_count} entities
            </span>
          </div>

          {status === 'completed' && threatLevel && threatLevel !== 'unknown' && (
            <ThreatBadge level={threatLevel} size="sm" />
          )}
        </div>

        {/* Footer */}
        <div className="px-4 py-2 border-t border-steel/50 flex items-center justify-between text-xs font-mono text-concrete bg-void/30">
          <div className="flex items-center gap-1.5">
            <Clock className="h-3 w-3" />
            <Timestamp date={created_at} format="relative" />
          </div>
          {duration_seconds && (
            <span>
              {duration_seconds < 60
                ? `${Math.round(duration_seconds)}s`
                : `${Math.round(duration_seconds / 60)}m ${Math.round(duration_seconds % 60)}s`}
            </span>
          )}
          <span className="text-steel font-mono text-[10px]">
            #{id.slice(0, 8)}
          </span>
        </div>
      </Card>
    </Link>
  );
}
