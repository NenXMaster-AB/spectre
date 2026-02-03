/**
 * WebSocket Client
 *
 * Handles real-time updates for investigations.
 */

import type { WSMessage } from '../types';

type WSEventHandler = (message: WSMessage) => void;
type WSCloseHandler = (code: number, reason: string) => void;
type WSErrorHandler = (error: Event) => void;

interface WSClientOptions {
  onMessage?: WSEventHandler;
  onClose?: WSCloseHandler;
  onError?: WSErrorHandler;
  onOpen?: () => void;
}

/**
 * Create a WebSocket connection for investigation updates.
 */
export function createInvestigationSocket(
  investigationId: string,
  options: WSClientOptions = {},
): WebSocket {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.host;
  const url = `${protocol}//${host}/api/v1/investigations/ws/${investigationId}`;

  const socket = new WebSocket(url);

  socket.onopen = () => {
    options.onOpen?.();
  };

  socket.onmessage = (event) => {
    try {
      const message = JSON.parse(event.data) as WSMessage;
      options.onMessage?.(message);
    } catch (error) {
      console.error('Failed to parse WebSocket message:', error);
    }
  };

  socket.onclose = (event) => {
    options.onClose?.(event.code, event.reason);
  };

  socket.onerror = (error) => {
    options.onError?.(error);
  };

  return socket;
}

/**
 * WebSocket manager for multiple investigations.
 */
export class InvestigationSocketManager {
  private sockets: Map<string, WebSocket> = new Map();
  private handlers: Map<string, Set<WSEventHandler>> = new Map();

  /**
   * Subscribe to updates for an investigation.
   */
  subscribe(investigationId: string, handler: WSEventHandler): () => void {
    // Add handler
    if (!this.handlers.has(investigationId)) {
      this.handlers.set(investigationId, new Set());
    }
    this.handlers.get(investigationId)!.add(handler);

    // Create socket if needed
    if (!this.sockets.has(investigationId)) {
      const socket = createInvestigationSocket(investigationId, {
        onMessage: (message) => {
          this.handlers.get(investigationId)?.forEach((h) => h(message));
        },
        onClose: (code) => {
          // Clean up on close
          if (code !== 1000) {
            // Abnormal close
            console.warn(`WebSocket closed with code ${code}`);
          }
          this.sockets.delete(investigationId);
        },
        onError: (error) => {
          console.error('WebSocket error:', error);
        },
      });
      this.sockets.set(investigationId, socket);
    }

    // Return unsubscribe function
    return () => {
      this.handlers.get(investigationId)?.delete(handler);

      // Close socket if no more handlers
      if (this.handlers.get(investigationId)?.size === 0) {
        this.sockets.get(investigationId)?.close(1000, 'Unsubscribed');
        this.sockets.delete(investigationId);
        this.handlers.delete(investigationId);
      }
    };
  }

  /**
   * Close all sockets.
   */
  closeAll(): void {
    this.sockets.forEach((socket) => socket.close(1000, 'Manager closed'));
    this.sockets.clear();
    this.handlers.clear();
  }
}

// Global socket manager instance
export const socketManager = new InvestigationSocketManager();
