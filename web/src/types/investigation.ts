/**
 * Investigation Types
 *
 * TypeScript types mirroring the API schemas for investigations.
 */

export type InvestigationStatus =
  | 'pending'
  | 'planning'
  | 'executing'
  | 'correlating'
  | 'enriching'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'clean' | 'unknown';

export type EntityType =
  | 'domain'
  | 'ip_address'
  | 'email'
  | 'hash'
  | 'url'
  | 'person'
  | 'organization'
  | 'certificate'
  | 'vulnerability'
  | 'threat_actor'
  | 'malware'
  | 'campaign';

export interface TargetEntity {
  type: string;
  value: string;
  confidence: number;
}

export interface Finding {
  id: string;
  type: string;
  source: string;
  data: Record<string, unknown>;
  confidence: number;
  threat_level: ThreatLevel;
  timestamp: string;
}

export interface FindingDetail extends Finding {
  is_ioc: boolean;
  raw_response?: Record<string, unknown>;
}

export interface DiscoveredEntity {
  id: string;
  type: string;
  value: string;
  source_plugin: string;
  confidence: number;
  properties: Record<string, unknown>;
  discovered_at: string;
}

export interface ThreatAssessment {
  threat_level: ThreatLevel;
  confidence_score: number;
  is_malicious: boolean;
  threat_types: string[];
  indicators_of_compromise: number;
  attributed_actors: string[];
  mitre_techniques: string[];
  summary: string;
}

export interface InvestigationEvent {
  id: string;
  type: string;
  timestamp: string;
  data: Record<string, unknown>;
}

export interface Investigation {
  id: string;
  query: string;
  target: TargetEntity;
  status: InvestigationStatus;
  progress: number;
  current_stage: string;
  error?: string;

  created_at: string;
  started_at?: string;
  completed_at?: string;
  duration_seconds?: number;

  plugins_total: number;
  plugins_completed: number;
  plugins_failed: number;

  findings: Finding[];
  entities: DiscoveredEntity[];
  threat_assessment?: ThreatAssessment;
  events: InvestigationEvent[];
}

export interface InvestigationSummary {
  id: string;
  query: string;
  target: TargetEntity;
  status: InvestigationStatus;
  progress: number;
  current_stage: string;
  threat_level: ThreatLevel;
  findings_count: number;
  entities_count: number;
  created_at: string;
  completed_at?: string;
  duration_seconds?: number;
}

export interface InvestigationProgress {
  id: string;
  status: InvestigationStatus;
  progress: number;
  current_stage: string;
  plugins_completed: number;
  plugins_total: number;
}

export interface InvestigationCreate {
  query: string;
  entity_type?: EntityType;
  entity_value?: string;
  depth?: 'quick' | 'standard' | 'full';
}

export interface InvestigationListResponse {
  items: InvestigationSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface FindingListResponse {
  investigation_id: string;
  findings: FindingDetail[];
  total: number;
  by_source: Record<string, number>;
  by_threat_level: Record<string, number>;
}

// WebSocket event types
export type WSEventType =
  | 'connection.established'
  | 'investigation.started'
  | 'investigation.completed'
  | 'investigation.failed'
  | 'investigation.cancelled'
  | 'stage.changed'
  | 'plan.created'
  | 'plugin.started'
  | 'plugin.completed'
  | 'plugin.failed'
  | 'finding.discovered'
  | 'entity.discovered'
  | 'threat.detected'
  | 'progress.updated';

export interface WSMessage {
  type: WSEventType;
  investigation_id: string;
  timestamp: string;
  data: Record<string, unknown>;
}
