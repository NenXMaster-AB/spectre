/**
 * Vignette - CRT monitor edge darkening effect
 *
 * Creates the subtle darkening around the edges that
 * suggests viewing through an old CRT monitor.
 */

interface VignetteProps {
  /** Intensity of the vignette effect (0-1) */
  intensity?: number;
}

export function Vignette({ intensity = 0.4 }: VignetteProps) {
  return (
    <div
      className="vignette"
      style={{
        background: `radial-gradient(
          ellipse at center,
          transparent 40%,
          rgba(0, 0, 0, ${intensity}) 100%
        )`,
      }}
      aria-hidden="true"
    />
  );
}
