/**
 * ScanLineOverlay - CRT scan line effect overlay
 *
 * Creates the classic CRT monitor scan line effect that adds
 * to the Cold War surveillance aesthetic.
 */

interface ScanLineOverlayProps {
  /** Whether to animate the scan lines */
  animated?: boolean;
  /** Intensity of the scan lines (0-1) */
  intensity?: number;
}

export function ScanLineOverlay({
  animated = false,
  intensity = 0.08,
}: ScanLineOverlayProps) {
  return (
    <div
      className={animated ? 'scan-lines' : 'scan-lines-static'}
      style={{
        '--scan-intensity': intensity,
      } as React.CSSProperties}
      aria-hidden="true"
    />
  );
}
