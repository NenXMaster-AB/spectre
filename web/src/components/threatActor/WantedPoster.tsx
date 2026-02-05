/**
 * WantedPoster - Dramatic threat actor card
 *
 * Styled as a classified dossier card with threat level,
 * country of origin, and key stats.
 */

import { Link } from 'react-router-dom';
import { Shield, MapPin, Crosshair, Wrench } from 'lucide-react';

interface WantedPosterProps {
  id: string;
  name: string;
  aliases: string[];
  country: string;
  description: string;
  ttpCount: number;
  toolCount: number;
  targetSectors: string[];
}

const COUNTRY_FLAGS: Record<string, string> = {
  RU: '🇷🇺',
  CN: '🇨🇳',
  KP: '🇰🇵',
  IR: '🇮🇷',
  US: '🇺🇸',
};

export function WantedPoster({
  id,
  name,
  aliases,
  country,
  description,
  ttpCount,
  toolCount,
  targetSectors,
}: WantedPosterProps) {
  return (
    <Link
      to={`/threat-actors/${id}`}
      className="block group"
    >
      <div className="relative bg-bunker border border-steel hover:border-blood/50 transition-colors">
        {/* Top accent */}
        <div className="absolute top-0 left-4 right-4 h-px bg-gradient-to-r from-transparent via-blood/50 to-transparent" />

        {/* Classification stamp */}
        <div className="absolute top-3 right-3 font-display text-[10px] tracking-widest text-blood/60 border border-blood/30 px-2 py-0.5 rotate-[-3deg]">
          CLASSIFIED
        </div>

        <div className="p-4 pt-6">
          {/* Actor identity */}
          <div className="flex items-start gap-3 mb-3">
            <div className="w-12 h-12 bg-slate border border-steel flex items-center justify-center shrink-0">
              <Shield className="w-6 h-6 text-blood" />
            </div>
            <div className="min-w-0">
              <h3 className="font-display text-xl tracking-wider text-paper group-hover:text-blood transition-colors truncate">
                {name}
              </h3>
              {aliases.length > 0 && (
                <p className="text-concrete text-xs font-mono truncate">
                  aka {aliases.slice(0, 3).join(', ')}
                </p>
              )}
            </div>
          </div>

          {/* Country */}
          {country && (
            <div className="flex items-center gap-1.5 mb-3 text-xs font-mono text-concrete">
              <MapPin className="w-3 h-3" />
              <span>{COUNTRY_FLAGS[country] || ''} {country}</span>
            </div>
          )}

          {/* Description */}
          <p className="text-concrete text-xs leading-relaxed mb-4 line-clamp-2 font-mono">
            {description}
          </p>

          {/* Stats row */}
          <div className="flex items-center gap-4 text-xs font-mono border-t border-steel pt-3">
            <div className="flex items-center gap-1 text-amber">
              <Crosshair className="w-3 h-3" />
              <span>{ttpCount} TTPs</span>
            </div>
            <div className="flex items-center gap-1 text-concrete">
              <Wrench className="w-3 h-3" />
              <span>{toolCount} tools</span>
            </div>
          </div>

          {/* Target sectors */}
          {targetSectors.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {targetSectors.slice(0, 3).map((sector) => (
                <span
                  key={sector}
                  className="text-[10px] font-mono px-1.5 py-0.5 bg-slate text-concrete border border-steel"
                >
                  {sector}
                </span>
              ))}
              {targetSectors.length > 3 && (
                <span className="text-[10px] font-mono text-concrete">
                  +{targetSectors.length - 3}
                </span>
              )}
            </div>
          )}
        </div>
      </div>
    </Link>
  );
}
