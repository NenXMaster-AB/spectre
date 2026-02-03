/**
 * Investigation WebSocket Hook
 *
 * React hook for real-time investigation updates via WebSocket.
 */

import { useEffect, useCallback, useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { socketManager } from '../api';
import { investigationKeys, isActiveStatus } from './useInvestigations';
import type { WSMessage, Investigation, InvestigationStatus } from '../types';

interface UseInvestigationSocketOptions {
  onMessage?: (message: WSMessage) => void;
  onStageChange?: (stage: string) => void;
  onProgress?: (progress: number) => void;
  onComplete?: (investigation: Investigation) => void;
  onError?: (error: string) => void;
  onFinding?: (finding: unknown) => void;
  onEntity?: (entity: unknown) => void;
}

/**
 * Hook to subscribe to real-time investigation updates.
 *
 * Automatically invalidates React Query caches when updates arrive.
 */
export function useInvestigationSocket(
  investigationId: string | undefined,
  status: InvestigationStatus | undefined,
  options: UseInvestigationSocketOptions = {},
) {
  const queryClient = useQueryClient();
  const optionsRef = useRef(options);
  optionsRef.current = options;

  const handleMessage = useCallback(
    (message: WSMessage) => {
      const { type, data } = message;

      // Call general message handler
      optionsRef.current.onMessage?.(message);

      // Handle specific event types
      switch (type) {
        case 'stage.changed':
          optionsRef.current.onStageChange?.(data.stage as string);
          break;

        case 'progress.updated':
          optionsRef.current.onProgress?.(data.progress as number);
          // Invalidate progress query
          if (investigationId) {
            queryClient.invalidateQueries({
              queryKey: investigationKeys.progress(investigationId),
            });
          }
          break;

        case 'investigation.completed':
        case 'investigation.failed':
        case 'investigation.cancelled':
          // Invalidate all related queries
          if (investigationId) {
            queryClient.invalidateQueries({
              queryKey: investigationKeys.detail(investigationId),
            });
            queryClient.invalidateQueries({
              queryKey: investigationKeys.lists(),
            });
          }
          if (type === 'investigation.completed') {
            optionsRef.current.onComplete?.(data as unknown as Investigation);
          } else if (type === 'investigation.failed') {
            optionsRef.current.onError?.(data.error as string);
          }
          break;

        case 'finding.discovered':
          optionsRef.current.onFinding?.(data.finding);
          // Invalidate findings query
          if (investigationId) {
            queryClient.invalidateQueries({
              queryKey: investigationKeys.findings(investigationId),
            });
          }
          break;

        case 'entity.discovered':
          optionsRef.current.onEntity?.(data.entity);
          break;

        case 'plugin.started':
        case 'plugin.completed':
        case 'plugin.failed':
          // Invalidate detail to get updated plugin counts
          if (investigationId) {
            queryClient.invalidateQueries({
              queryKey: investigationKeys.detail(investigationId),
            });
          }
          break;
      }
    },
    [investigationId, queryClient],
  );

  useEffect(() => {
    // Only connect if investigation is active
    if (!investigationId || !status || !isActiveStatus(status)) {
      return;
    }

    const unsubscribe = socketManager.subscribe(investigationId, handleMessage);

    return () => {
      unsubscribe();
    };
  }, [investigationId, status, handleMessage]);
}

/**
 * Hook for simpler polling-based updates (fallback for when WebSocket fails).
 */
export function useInvestigationPolling(
  investigationId: string | undefined,
  status: InvestigationStatus | undefined,
  intervalMs: number = 2000,
) {
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!investigationId || !status || !isActiveStatus(status)) {
      return;
    }

    const interval = setInterval(() => {
      queryClient.invalidateQueries({
        queryKey: investigationKeys.detail(investigationId),
      });
      queryClient.invalidateQueries({
        queryKey: investigationKeys.progress(investigationId),
      });
    }, intervalMs);

    return () => clearInterval(interval);
  }, [investigationId, status, intervalMs, queryClient]);
}
