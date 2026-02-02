/**
 * Timestamp - CCTV-style timestamp display
 *
 * Features:
 * - Monospace font for technical feel
 * - Recording indicator option
 * - Multiple format options
 * - Live updating option
 */

import { useState, useEffect } from 'react';

type TimestampFormat = 'iso' | 'datetime' | 'date' | 'time' | 'relative';

interface TimestampProps {
  /** The date to display. If not provided, shows current time */
  date?: Date | string;
  /** Format to display */
  format?: TimestampFormat;
  /** Show recording indicator */
  recording?: boolean;
  /** Update the timestamp live (only for current time) */
  live?: boolean;
  /** Additional CSS classes */
  className?: string;
  /** Prefix text before the timestamp */
  prefix?: string;
}

function formatDate(date: Date, format: TimestampFormat): string {
  switch (format) {
    case 'iso':
      return date.toISOString().replace('T', ' ').slice(0, 19);
    case 'datetime':
      return date.toLocaleString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      });
    case 'date':
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
      });
    case 'time':
      return date.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      });
    case 'relative':
      return getRelativeTime(date);
    default:
      return date.toISOString();
  }
}

function getRelativeTime(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHour / 24);

  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffHour < 24) return `${diffHour}h ago`;
  if (diffDay < 7) return `${diffDay}d ago`;
  return date.toLocaleDateString();
}

export function Timestamp({
  date,
  format = 'iso',
  recording = false,
  live = false,
  className = '',
  prefix,
}: TimestampProps) {
  const [currentDate, setCurrentDate] = useState(
    date ? new Date(date) : new Date()
  );

  useEffect(() => {
    if (!live || date) return;

    const timer = setInterval(() => {
      setCurrentDate(new Date());
    }, 1000);

    return () => clearInterval(timer);
  }, [live, date]);

  // If date prop changes, update currentDate
  useEffect(() => {
    if (date) {
      setCurrentDate(new Date(date));
    }
  }, [date]);

  return (
    <span
      className={`
        timestamp-cctv
        ${recording ? 'recording' : ''}
        ${className}
      `}
    >
      {prefix && <span className="text-concrete mr-1">{prefix}</span>}
      {formatDate(currentDate, format)}
    </span>
  );
}
