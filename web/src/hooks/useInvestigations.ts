/**
 * Investigation Hooks
 *
 * React Query hooks for investigation data fetching and mutations.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  listInvestigations,
  getInvestigation,
  startInvestigation,
  cancelInvestigation,
  getInvestigationFindings,
  getInvestigationProgress,
  type ListInvestigationsParams,
} from '../api';
import type { InvestigationCreate, InvestigationStatus } from '../types';

// Query keys factory
export const investigationKeys = {
  all: ['investigations'] as const,
  lists: () => [...investigationKeys.all, 'list'] as const,
  list: (params: ListInvestigationsParams) => [...investigationKeys.lists(), params] as const,
  details: () => [...investigationKeys.all, 'detail'] as const,
  detail: (id: string) => [...investigationKeys.details(), id] as const,
  progress: (id: string) => [...investigationKeys.all, 'progress', id] as const,
  findings: (id: string) => [...investigationKeys.all, 'findings', id] as const,
};

/**
 * Hook to list investigations with optional filtering.
 */
export function useInvestigations(params: ListInvestigationsParams = {}) {
  return useQuery({
    queryKey: investigationKeys.list(params),
    queryFn: () => listInvestigations(params),
  });
}

/**
 * Hook to get a single investigation by ID.
 */
export function useInvestigation(id: string | undefined) {
  return useQuery({
    queryKey: investigationKeys.detail(id!),
    queryFn: () => getInvestigation(id!),
    enabled: !!id,
  });
}

/**
 * Hook to get investigation progress (lightweight polling).
 */
export function useInvestigationProgress(
  id: string | undefined,
  options?: { enabled?: boolean; refetchInterval?: number },
) {
  return useQuery({
    queryKey: investigationKeys.progress(id!),
    queryFn: () => getInvestigationProgress(id!),
    enabled: !!id && (options?.enabled ?? true),
    refetchInterval: options?.refetchInterval,
  });
}

/**
 * Hook to get investigation findings.
 */
export function useInvestigationFindings(id: string | undefined) {
  return useQuery({
    queryKey: investigationKeys.findings(id!),
    queryFn: () => getInvestigationFindings(id!),
    enabled: !!id,
  });
}

/**
 * Hook to start a new investigation.
 */
export function useStartInvestigation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: InvestigationCreate) => startInvestigation(data),
    onSuccess: () => {
      // Invalidate list queries to show new investigation
      queryClient.invalidateQueries({ queryKey: investigationKeys.lists() });
    },
  });
}

/**
 * Hook to cancel an investigation.
 */
export function useCancelInvestigation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => cancelInvestigation(id),
    onSuccess: (_, id) => {
      // Invalidate specific investigation and lists
      queryClient.invalidateQueries({ queryKey: investigationKeys.detail(id) });
      queryClient.invalidateQueries({ queryKey: investigationKeys.lists() });
    },
  });
}

/**
 * Check if an investigation status is active (running).
 */
export function isActiveStatus(status: InvestigationStatus): boolean {
  return ['pending', 'planning', 'executing', 'correlating', 'enriching'].includes(status);
}
