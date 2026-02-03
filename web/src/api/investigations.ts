/**
 * Investigations API
 *
 * API functions for investigation operations.
 */

import { api } from './client';
import type {
  Investigation,
  InvestigationCreate,
  InvestigationListResponse,
  InvestigationProgress,
  FindingListResponse,
  InvestigationStatus,
} from '../types';

export interface ListInvestigationsParams {
  status?: InvestigationStatus;
  limit?: number;
  offset?: number;
}

/**
 * Start a new investigation.
 */
export async function startInvestigation(data: InvestigationCreate): Promise<Investigation> {
  return api.post<Investigation>('/investigations', data);
}

/**
 * List investigations with optional filtering.
 */
export async function listInvestigations(
  params: ListInvestigationsParams = {},
): Promise<InvestigationListResponse> {
  const searchParams = new URLSearchParams();
  if (params.status) searchParams.set('status', params.status);
  if (params.limit) searchParams.set('limit', params.limit.toString());
  if (params.offset) searchParams.set('offset', params.offset.toString());

  const query = searchParams.toString();
  const endpoint = query ? `/investigations?${query}` : '/investigations';
  return api.get<InvestigationListResponse>(endpoint);
}

/**
 * Get investigation by ID.
 */
export async function getInvestigation(id: string): Promise<Investigation> {
  return api.get<Investigation>(`/investigations/${id}`);
}

/**
 * Get lightweight progress update.
 */
export async function getInvestigationProgress(id: string): Promise<InvestigationProgress> {
  return api.get<InvestigationProgress>(`/investigations/${id}/progress`);
}

/**
 * Cancel a running investigation.
 */
export async function cancelInvestigation(id: string): Promise<void> {
  return api.delete(`/investigations/${id}`);
}

/**
 * Get all findings for an investigation.
 */
export async function getInvestigationFindings(id: string): Promise<FindingListResponse> {
  return api.get<FindingListResponse>(`/investigations/${id}/findings`);
}
