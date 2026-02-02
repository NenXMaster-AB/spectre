/**
 * GrainTexture - Analog film grain overlay
 *
 * Adds subtle noise texture for that authentic analog
 * surveillance footage feel.
 */

interface GrainTextureProps {
  /** Opacity of the grain effect (0-1) */
  opacity?: number;
}

export function GrainTexture({ opacity = 0.03 }: GrainTextureProps) {
  return (
    <div
      className="grain"
      style={{ opacity }}
      aria-hidden="true"
    />
  );
}
