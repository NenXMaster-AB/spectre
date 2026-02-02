/**
 * Header - Top navigation bar with SPECTRE branding
 *
 * Features:
 * - SPECTRE logo and title
 * - CCTV-style live timestamp
 * - System status indicator
 */

import { useState, useEffect } from 'react';
import { Activity, Wifi, WifiOff } from 'lucide-react';

interface HeaderProps {
  /** Whether the system is connected to the backend */
  isConnected?: boolean;
}

export function Header({ isConnected = true }: HeaderProps) {
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  const formatTimestamp = (date: Date) => {
    return date.toISOString().replace('T', ' ').slice(0, 19);
  };

  return (
    <header className="h-14 bg-bunker border-b border-steel flex items-center justify-between px-6">
      {/* Logo and Title */}
      <div className="flex items-center gap-4">
        <img
          src="/spectre-logo.svg"
          alt="SPECTRE"
          className="h-8 w-8"
        />
        <div className="flex flex-col">
          <h1 className="text-xl font-display tracking-widest text-phosphor glow-phosphor-subtle">
            SPECTRE
          </h1>
          <span className="text-[10px] font-mono text-concrete -mt-1 tracking-wider">
            INTELLIGENCE PLATFORM
          </span>
        </div>
      </div>

      {/* Center - System Status */}
      <div className="flex items-center gap-6">
        <div className="flex items-center gap-2">
          <Activity
            className={`h-4 w-4 ${isConnected ? 'text-phosphor animate-pulse' : 'text-blood'}`}
          />
          <span className="text-xs font-mono text-concrete">
            {isConnected ? 'SYSTEMS OPERATIONAL' : 'CONNECTION LOST'}
          </span>
        </div>
      </div>

      {/* Right - Timestamp */}
      <div className="flex items-center gap-4">
        {/* Connection Status */}
        <div className="flex items-center gap-2">
          {isConnected ? (
            <Wifi className="h-4 w-4 text-phosphor" />
          ) : (
            <WifiOff className="h-4 w-4 text-blood" />
          )}
        </div>

        {/* CCTV Timestamp */}
        <div className="timestamp-cctv recording">
          {formatTimestamp(currentTime)}
        </div>
      </div>
    </header>
  );
}
