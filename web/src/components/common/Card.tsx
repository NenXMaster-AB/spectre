/**
 * Card - Dossier-style card container
 *
 * Features:
 * - Hard edges (brutalist, no rounded corners)
 * - Optional phosphor accent line at top
 * - Folder-tab header option
 * - Classified stamp overlay option
 */

import { forwardRef } from 'react';
import { ClassifiedStamp, type StampType } from './ClassifiedStamp';

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Card title displayed in folder-tab style header */
  title?: string;
  /** Optional subtitle */
  subtitle?: string;
  /** Show the phosphor accent line at top */
  showAccent?: boolean;
  /** Optional classified stamp overlay */
  stamp?: StampType;
  /** Whether the card is in a selected/active state */
  isActive?: boolean;
  /** Padding size */
  padding?: 'none' | 'sm' | 'md' | 'lg';
}

const paddingStyles = {
  none: '',
  sm: 'p-3',
  md: 'p-4',
  lg: 'p-6',
};

export const Card = forwardRef<HTMLDivElement, CardProps>(
  (
    {
      title,
      subtitle,
      showAccent = true,
      stamp,
      isActive = false,
      padding = 'md',
      children,
      className = '',
      ...props
    },
    ref
  ) => {
    return (
      <div
        ref={ref}
        className={`
          relative bg-bunker border border-steel
          ${isActive ? 'border-phosphor box-glow-phosphor' : ''}
          ${className}
        `}
        {...props}
      >
        {/* Phosphor accent line */}
        {showAccent && (
          <div className="absolute top-0 left-4 right-4 h-px bg-gradient-to-r from-transparent via-phosphor/50 to-transparent" />
        )}

        {/* Classified stamp */}
        {stamp && (
          <ClassifiedStamp
            type={stamp}
            className="top-4 right-4"
          />
        )}

        {/* Header */}
        {title && (
          <div className="px-4 py-3 border-b border-steel">
            <h3 className="font-display text-lg tracking-wider text-paper">
              {title}
            </h3>
            {subtitle && (
              <p className="text-xs font-mono text-concrete mt-0.5">
                {subtitle}
              </p>
            )}
          </div>
        )}

        {/* Content */}
        <div className={paddingStyles[padding]}>{children}</div>
      </div>
    );
  }
);

Card.displayName = 'Card';
