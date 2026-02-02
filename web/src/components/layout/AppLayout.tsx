/**
 * AppLayout - Main application shell
 *
 * Combines all layout components:
 * - Header with SPECTRE branding
 * - Sidebar navigation
 * - Main content area
 * - CRT overlay effects (scan lines, grain, vignette)
 */

import { Outlet } from 'react-router-dom';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { ScanLineOverlay } from './ScanLineOverlay';
import { GrainTexture } from './GrainTexture';
import { Vignette } from './Vignette';

interface AppLayoutProps {
  /** Whether to show CRT effects */
  showEffects?: boolean;
  /** Whether the system is connected */
  isConnected?: boolean;
}

export function AppLayout({
  showEffects = true,
  isConnected = true,
}: AppLayoutProps) {
  return (
    <div className="min-h-screen bg-void text-paper flex flex-col">
      {/* CRT Effects Overlays */}
      {showEffects && (
        <>
          <ScanLineOverlay animated={false} />
          <GrainTexture opacity={0.025} />
          <Vignette intensity={0.35} />
        </>
      )}

      {/* Header */}
      <Header isConnected={isConnected} />

      {/* Main Content Area */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <Sidebar />

        {/* Page Content */}
        <main className="flex-1 overflow-auto bg-void">
          <div className="p-6 min-h-full">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
