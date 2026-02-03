/**
 * ProgressBar - SPECTRE-styled progress indicator
 *
 * Features:
 * - Phosphor glow effect on active progress
 * - Stage label display
 * - Segmented or continuous styles
 */

interface ProgressBarProps {
  /** Progress value from 0 to 1 */
  progress: number;
  /** Current stage label */
  stage?: string;
  /** Show percentage text */
  showPercentage?: boolean;
  /** Height variant */
  size?: 'sm' | 'md' | 'lg';
  /** Use segmented style */
  segmented?: boolean;
  className?: string;
}

const sizeStyles = {
  sm: 'h-1',
  md: 'h-2',
  lg: 'h-3',
};

export function ProgressBar({
  progress,
  stage,
  showPercentage = false,
  size = 'md',
  segmented = false,
  className = '',
}: ProgressBarProps) {
  const percentage = Math.round(progress * 100);
  const isActive = progress > 0 && progress < 1;

  if (segmented) {
    // 5-segment progress bar (one per stage)
    const segments = 5;
    const filledSegments = Math.ceil(progress * segments);

    return (
      <div className={className}>
        <div className="flex gap-1">
          {Array.from({ length: segments }).map((_, i) => (
            <div
              key={i}
              className={`
                flex-1 ${sizeStyles[size]}
                ${i < filledSegments ? 'bg-phosphor' : 'bg-steel'}
                ${i === filledSegments - 1 && isActive ? 'animate-pulse box-glow-phosphor' : ''}
              `}
            />
          ))}
        </div>
        {(stage || showPercentage) && (
          <div className="flex justify-between mt-1.5 text-xs font-mono">
            {stage && <span className="text-phosphor uppercase">{stage}</span>}
            {showPercentage && <span className="text-concrete">{percentage}%</span>}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className={className}>
      <div className={`w-full bg-steel ${sizeStyles[size]} relative overflow-hidden`}>
        <div
          className={`
            h-full bg-phosphor transition-all duration-300
            ${isActive ? 'box-glow-phosphor' : ''}
          `}
          style={{ width: `${percentage}%` }}
        />
        {/* Scanline effect on active progress */}
        {isActive && (
          <div
            className="absolute inset-0 bg-gradient-to-b from-transparent via-white/10 to-transparent animate-scan-fast"
            style={{ backgroundSize: '100% 4px' }}
          />
        )}
      </div>
      {(stage || showPercentage) && (
        <div className="flex justify-between mt-1.5 text-xs font-mono">
          {stage && <span className="text-phosphor uppercase tracking-wide">{stage}</span>}
          {showPercentage && <span className="text-concrete">{percentage}%</span>}
        </div>
      )}
    </div>
  );
}
