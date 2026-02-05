/**
 * ThreatActorDetail - Full actor dossier page
 *
 * Phase 5.4: Classified dossier-style threat actor profile.
 */

import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Card } from '../components/common';
import {
  ArrowLeft, Shield, MapPin, Wrench,
  Target, Globe, AlertTriangle,
} from 'lucide-react';
import { api } from '../api/client';

interface ThreatActorProfile {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  country: string;
  active: boolean;
  techniques: string[];
  tools: string[];
  infrastructure: string[];
  target_sectors: string[];
  target_countries: string[];
  references: string[];
}

const COUNTRY_NAMES: Record<string, string> = {
  RU: 'Russia',
  CN: 'China',
  KP: 'North Korea',
  IR: 'Iran',
  US: 'United States',
};

export function ThreatActorDetail() {
  const { id } = useParams<{ id: string }>();

  const { data: actor, isLoading, error } = useQuery<ThreatActorProfile>({
    queryKey: ['threat-actor', id],
    queryFn: () => api.get(`/threat-actors/${id}`),
    enabled: !!id,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="text-concrete font-mono text-sm animate-pulse">
          DECRYPTING DOSSIER...
        </div>
      </div>
    );
  }

  if (error || !actor) {
    return (
      <div className="space-y-6">
        <Link to="/threat-actors" className="flex items-center gap-2 text-concrete hover:text-paper font-mono text-sm">
          <ArrowLeft className="w-4 h-4" /> Back to Threat Actors
        </Link>
        <Card>
          <div className="flex items-center gap-3 text-blood py-8 justify-center">
            <AlertTriangle className="w-5 h-5" />
            <span className="font-mono text-sm">DOSSIER NOT FOUND</span>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Back link */}
      <Link to="/threat-actors" className="flex items-center gap-2 text-concrete hover:text-paper font-mono text-sm">
        <ArrowLeft className="w-4 h-4" /> Back to Threat Actors
      </Link>

      {/* Header */}
      <Card showAccent stamp="top-secret" padding="lg">
        <div className="flex items-start gap-4">
          <div className="w-16 h-16 bg-slate border border-blood/30 flex items-center justify-center shrink-0">
            <Shield className="w-8 h-8 text-blood" />
          </div>
          <div className="flex-1 min-w-0">
            <h1 className="text-4xl font-display tracking-wider text-paper">
              {actor.name}
            </h1>
            {actor.aliases.length > 0 && (
              <p className="text-concrete font-mono text-sm mt-1">
                AKA: {actor.aliases.join(' / ')}
              </p>
            )}
            <div className="flex items-center gap-4 mt-3 text-sm font-mono">
              {actor.country && (
                <span className="flex items-center gap-1 text-concrete">
                  <MapPin className="w-3.5 h-3.5" />
                  {COUNTRY_NAMES[actor.country] || actor.country}
                </span>
              )}
              <span className={`flex items-center gap-1 ${actor.active ? 'text-blood' : 'text-concrete'}`}>
                <span className={`w-2 h-2 rounded-full ${actor.active ? 'bg-blood animate-pulse' : 'bg-steel'}`} />
                {actor.active ? 'ACTIVE' : 'INACTIVE'}
              </span>
            </div>
          </div>
        </div>
      </Card>

      {/* Description */}
      {actor.description && (
        <Card title="INTELLIGENCE SUMMARY" showAccent>
          <p className="text-paper font-mono text-sm leading-relaxed">
            {actor.description}
          </p>
        </Card>
      )}

      {/* Two-column layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* TTPs */}
        <Card title="MITRE ATT&CK TECHNIQUES" subtitle={`${actor.techniques.length} known techniques`} showAccent>
          {actor.techniques.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {actor.techniques.map((tech) => (
                <span
                  key={tech}
                  className="px-2 py-1 bg-slate border border-steel text-amber font-mono text-xs hover:border-amber/50 transition-colors cursor-default"
                  title={tech}
                >
                  {tech}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-concrete font-mono text-sm">No techniques recorded</p>
          )}
        </Card>

        {/* Arsenal */}
        <Card title="ARSENAL" subtitle="Known tools and malware" showAccent>
          {actor.tools.length > 0 ? (
            <div className="space-y-2">
              {actor.tools.map((tool) => (
                <div
                  key={tool}
                  className="flex items-center gap-2 px-3 py-2 bg-slate border border-steel"
                >
                  <Wrench className="w-3.5 h-3.5 text-signal shrink-0" />
                  <span className="font-mono text-sm text-paper">{tool}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-concrete font-mono text-sm">No tools recorded</p>
          )}
        </Card>

        {/* Targeting */}
        <Card title="VICTIMOLOGY" subtitle="Target sectors and regions" showAccent>
          <div className="space-y-4">
            {actor.target_sectors.length > 0 && (
              <div>
                <span className="text-xs font-mono text-concrete uppercase">Target Sectors</span>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {actor.target_sectors.map((sector) => (
                    <span
                      key={sector}
                      className="px-2 py-1 bg-slate border border-steel text-paper font-mono text-xs"
                    >
                      <Target className="w-3 h-3 inline mr-1 text-blood" />
                      {sector}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {actor.target_countries.length > 0 && (
              <div>
                <span className="text-xs font-mono text-concrete uppercase">Target Countries</span>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {actor.target_countries.map((country) => (
                    <span
                      key={country}
                      className="px-2 py-1 bg-slate border border-steel text-paper font-mono text-xs"
                    >
                      <Globe className="w-3 h-3 inline mr-1 text-radar" />
                      {country}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Card>

        {/* Infrastructure */}
        {actor.infrastructure.length > 0 && (
          <Card title="KNOWN INFRASTRUCTURE" showAccent>
            <div className="space-y-1">
              {actor.infrastructure.map((item, i) => (
                <div key={i} className="px-3 py-1.5 bg-slate border border-steel font-mono text-xs text-paper">
                  {item}
                </div>
              ))}
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}
