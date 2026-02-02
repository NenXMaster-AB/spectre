/**
 * ClassifiedStamp - Rubber stamp overlay
 *
 * Features:
 * - Multiple stamp types (TOP SECRET, EYES ONLY, CONFIDENTIAL, etc.)
 * - Rotated, distressed appearance
 * - Customizable positioning
 */

export type StampType =
  | 'top-secret'
  | 'eyes-only'
  | 'confidential'
  | 'classified'
  | 'threat-confirmed'
  | 'compromised'
  | 'neutralized';

interface ClassifiedStampProps {
  type: StampType;
  /** Additional CSS classes for positioning */
  className?: string;
  /** Size variant */
  size?: 'sm' | 'md' | 'lg';
  /** Rotation angle in degrees */
  rotation?: number;
}

const stampConfig: Record<StampType, { text: string; colorClass: string }> = {
  'top-secret': {
    text: 'TOP SECRET',
    colorClass: 'stamp-top-secret',
  },
  'eyes-only': {
    text: 'EYES ONLY',
    colorClass: 'stamp-eyes-only',
  },
  confidential: {
    text: 'CONFIDENTIAL',
    colorClass: 'stamp-confidential',
  },
  classified: {
    text: 'CLASSIFIED',
    colorClass: 'stamp-top-secret',
  },
  'threat-confirmed': {
    text: 'THREAT CONFIRMED',
    colorClass: 'stamp-top-secret',
  },
  compromised: {
    text: 'COMPROMISED',
    colorClass: 'stamp-top-secret',
  },
  neutralized: {
    text: 'NEUTRALIZED',
    colorClass: 'text-phosphor/60 border-phosphor/60',
  },
};

const sizeClasses = {
  sm: 'text-sm px-2 py-0.5 border-2',
  md: 'text-xl px-3 py-1 border-3',
  lg: 'text-3xl px-4 py-1.5 border-4',
};

export function ClassifiedStamp({
  type,
  className = '',
  size = 'md',
  rotation = -12,
}: ClassifiedStampProps) {
  const config = stampConfig[type];

  return (
    <div
      className={`
        classified-stamp
        ${config.colorClass}
        ${sizeClasses[size]}
        ${className}
      `}
      style={{ transform: `rotate(${rotation}deg)` }}
      aria-hidden="true"
    >
      {config.text}
    </div>
  );
}
