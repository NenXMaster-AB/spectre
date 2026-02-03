/**
 * InvestigationDetail - Single investigation view
 *
 * Features:
 * - Real-time progress via WebSocket
 * - Timeline of events
 * - Findings table
 * - Threat assessment summary
 */

import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  ArrowLeft,
  Target,
  Clock,
  FileText,
  Network,
  AlertTriangle,
  XCircle,
  RefreshCw,
} from 'lucide-react';
import { Card, Button, ThreatBadge, Timestamp } from '../components/common';
import {
  StatusIndicator,
  ProgressBar,
  InvestigationTimeline,
  FindingsTable,
} from '../components/investigations';
import {
  useInvestigation,
  useCancelInvestigation,
  isActiveStatus,
} from '../hooks';
import { useInvestigationSocket } from '../hooks/useInvestigationSocket';
import type { ThreatLevel } from '../types';

export function InvestigationDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const { data: investigation, isLoading, error, refetch } = useInvestigation(id);
  const cancelMutation = useCancelInvestigation();

  // Real-time updates via WebSocket
  useInvestigationSocket(id, investigation?.status, {
    onComplete: () => refetch(),
    onError: () => refetch(),
  });

  const handleCancel = async () => {
    if (!id || !investigation) return;
    if (!confirm('Cancel this investigation?')) return;

    try {
      await cancelMutation.mutateAsync(id);
      refetch();
    } catch (err) {
      console.error('Failed to cancel:', err);
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-steel/50 rounded w-1/3" />
          <div className="h-4 bg-steel/30 rounded w-1/2" />
          <Card showAccent padding="lg">
            <div className="space-y-3">
              <div className="h-4 bg-steel/50 rounded w-3/4" />
              <div className="h-3 bg-steel/30 rounded w-1/2" />
            </div>
          </Card>
        </div>
      </div>
    );
  }

  if (error || !investigation) {
    return (
      <div className="space-y-6">
        <Link
          to="/investigations"
          className="inline-flex items-center gap-2 text-concrete hover:text-phosphor transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          <span className="font-mono text-sm">Back to Investigations</span>
        </Link>
        <Card showAccent>
          <div className="text-center py-12">
            <XCircle className="h-12 w-12 text-blood mx-auto mb-4" />
            <p className="text-blood font-mono">
              {error ? (error as Error).message : 'Investigation not found'}
            </p>
            <Button
              variant="ghost"
              onClick={() => navigate('/investigations')}
              className="mt-4"
            >
              Return to Investigations
            </Button>
          </div>
        </Card>
      </div>
    );
  }

  const isActive = isActiveStatus(investigation.status);
  const threatLevel = investigation.threat_assessment?.threat_level as ThreatLevel;

  return (
    <div className="space-y-6">
      {/* Back Link */}
      <Link
        to="/investigations"
        className="inline-flex items-center gap-2 text-concrete hover:text-phosphor transition-colors"
      >
        <ArrowLeft className="h-4 w-4" />
        <span className="font-mono text-sm">Back to Investigations</span>
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-2">
            <Target className="h-6 w-6 text-phosphor flex-shrink-0" />
            <h1 className="text-2xl font-display tracking-wider text-paper truncate">
              {investigation.target.value}
            </h1>
            <span className="text-xs font-mono text-concrete uppercase bg-steel/30 px-2 py-0.5">
              {investigation.target.type}
            </span>
          </div>
          <p className="text-concrete font-mono text-sm">{investigation.query}</p>
          <div className="flex items-center gap-4 mt-2 text-xs font-mono text-steel">
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              <Timestamp date={investigation.created_at} format="relative" />
            </span>
            <span>ID: {investigation.id.slice(0, 12)}...</span>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <StatusIndicator status={investigation.status} />
          {isActive && (
            <Button
              variant="danger"
              onClick={handleCancel}
              disabled={cancelMutation.isPending}
            >
              Cancel
            </Button>
          )}
          <Button variant="ghost" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Progress (active investigations) */}
      {isActive && (
        <Card showAccent isActive padding="lg">
          <ProgressBar
            progress={investigation.progress}
            stage={investigation.current_stage}
            showPercentage
            segmented
          />
          <div className="mt-4 flex items-center justify-between text-xs font-mono text-concrete">
            <span>
              {investigation.plugins_completed} / {investigation.plugins_total} plugins completed
            </span>
            {investigation.plugins_failed > 0 && (
              <span className="text-signal">
                {investigation.plugins_failed} failed
              </span>
            )}
          </div>
        </Card>
      )}

      {/* Error (failed investigations) */}
      {investigation.status === 'failed' && investigation.error && (
        <Card showAccent stamp="classified">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-blood flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="font-display text-blood tracking-wider mb-1">
                INVESTIGATION FAILED
              </h3>
              <p className="font-mono text-sm text-concrete">
                {investigation.error}
              </p>
            </div>
          </div>
        </Card>
      )}

      {/* Threat Assessment (completed investigations) */}
      {investigation.threat_assessment && (
        <Card
          title="THREAT ASSESSMENT"
          showAccent
          stamp={threatLevel === 'critical' || threatLevel === 'high' ? 'classified' : undefined}
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <ThreatBadge level={threatLevel} size="lg" pulse />
              <span className="text-xs font-mono text-concrete">
                Confidence: {Math.round(investigation.threat_assessment.confidence_score * 100)}%
              </span>
            </div>
            <p className="font-mono text-sm text-paper leading-relaxed">
              {investigation.threat_assessment.summary}
            </p>
            {investigation.threat_assessment.threat_types.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {investigation.threat_assessment.threat_types.map((type) => (
                  <span
                    key={type}
                    className="px-2 py-0.5 text-xs font-mono bg-blood/20 text-blood border border-blood/50"
                  >
                    {type}
                  </span>
                ))}
              </div>
            )}
            <div className="grid grid-cols-3 gap-4 pt-4 border-t border-steel/50">
              <div className="text-center">
                <div className="text-2xl font-display text-phosphor">
                  {investigation.threat_assessment.indicators_of_compromise}
                </div>
                <div className="text-xs font-mono text-concrete">IOCs</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-display text-amber">
                  {investigation.threat_assessment.attributed_actors.length}
                </div>
                <div className="text-xs font-mono text-concrete">Actors</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-display text-radar">
                  {investigation.threat_assessment.mitre_techniques.length}
                </div>
                <div className="text-xs font-mono text-concrete">TTPs</div>
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Findings */}
        <div className="lg:col-span-2">
          <Card title="FINDINGS" subtitle={`${investigation.findings.length} total`} showAccent>
            <FindingsTable findings={investigation.findings} />
          </Card>
        </div>

        {/* Timeline */}
        <div>
          <Card title="TIMELINE" showAccent>
            <InvestigationTimeline
              events={investigation.events}
              maxHeight="500px"
            />
          </Card>
        </div>
      </div>

      {/* Discovered Entities */}
      {investigation.entities.length > 0 && (
        <Card
          title="DISCOVERED ENTITIES"
          subtitle={`${investigation.entities.length} total`}
          showAccent
        >
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {investigation.entities.map((entity) => (
              <div
                key={entity.id}
                className="p-3 bg-void border border-steel/50 hover:border-phosphor/50 transition-colors"
              >
                <div className="flex items-center gap-2 mb-1">
                  <Network className="h-4 w-4 text-radar" />
                  <span className="text-xs font-mono text-concrete uppercase">
                    {entity.type}
                  </span>
                </div>
                <p className="font-mono text-sm text-paper truncate">
                  {entity.value}
                </p>
                <p className="text-xs font-mono text-steel mt-1">
                  via {entity.source_plugin}
                </p>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Stats Footer */}
      <div className="flex items-center justify-between py-4 border-t border-steel/50 text-xs font-mono text-concrete">
        <div className="flex items-center gap-6">
          <span className="flex items-center gap-1.5">
            <FileText className="h-3.5 w-3.5" />
            {investigation.findings.length} findings
          </span>
          <span className="flex items-center gap-1.5">
            <Network className="h-3.5 w-3.5" />
            {investigation.entities.length} entities
          </span>
        </div>
        {investigation.duration_seconds && (
          <span>
            Duration:{' '}
            {investigation.duration_seconds < 60
              ? `${Math.round(investigation.duration_seconds)}s`
              : `${Math.round(investigation.duration_seconds / 60)}m ${Math.round(investigation.duration_seconds % 60)}s`}
          </span>
        )}
      </div>
    </div>
  );
}
