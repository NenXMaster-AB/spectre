/**
 * ThreatActors - Adversary dossier gallery
 *
 * Phase 5.4: Grid of WantedPoster cards with search and filtering.
 */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Card, Button } from '../components/common';
import { WantedPoster } from '../components/threatActor';
import { Users, Search, AlertTriangle } from 'lucide-react';
import { api } from '../api/client';

interface ThreatActorSummary {
  id: string;
  name: string;
  aliases: string[];
  country: string;
  active: boolean;
  ttp_count: number;
  tool_count: number;
  target_sectors: string[];
  target_countries: string[];
  description: string;
}

interface ThreatActorListResponse {
  actors: ThreatActorSummary[];
  total: number;
}

export function ThreatActors() {
  const [searchQuery, setSearchQuery] = useState('');
  const [sectorFilter, setSectorFilter] = useState('');

  const { data, isLoading, error } = useQuery<ThreatActorListResponse>({
    queryKey: ['threat-actors', searchQuery, sectorFilter],
    queryFn: () => {
      const params = new URLSearchParams();
      if (searchQuery) params.set('q', searchQuery);
      if (sectorFilter) params.set('sector', sectorFilter);
      return api.get(`/threat-actors?${params}`);
    },
  });

  const sectors = [
    'government', 'military', 'financial', 'technology',
    'healthcare', 'retail', 'media', 'defense',
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-display tracking-wider text-paper">
            THREAT ACTORS
          </h1>
          <p className="text-concrete font-mono text-sm mt-1">
            Adversary Intelligence Dossiers &mdash;{' '}
            {data?.total ?? 0} known actors
          </p>
        </div>
      </div>

      {/* Search and Filter Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-concrete" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search actors by name or alias..."
            className="w-full bg-bunker border border-steel pl-10 pr-4 py-2 text-paper font-mono text-sm placeholder:text-steel focus:border-blood focus:outline-none"
          />
        </div>

        <div className="flex flex-wrap items-center gap-1">
          <Button
            variant={!sectorFilter ? 'primary' : 'ghost'}
            onClick={() => setSectorFilter('')}
          >
            All Sectors
          </Button>
          {sectors.slice(0, 4).map((sector) => (
            <Button
              key={sector}
              variant={sectorFilter === sector ? 'danger' : 'ghost'}
              onClick={() => setSectorFilter(sectorFilter === sector ? '' : sector)}
            >
              {sector}
            </Button>
          ))}
        </div>
      </div>

      {/* Loading */}
      {isLoading && (
        <div className="flex items-center justify-center py-16">
          <div className="text-concrete font-mono text-sm animate-pulse">
            LOADING DOSSIERS...
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <Card>
          <div className="flex items-center gap-3 text-blood">
            <AlertTriangle className="w-5 h-5 shrink-0" />
            <span className="font-mono text-sm">Failed to load threat actors</span>
          </div>
        </Card>
      )}

      {/* Actor Grid */}
      {data && data.actors.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {data.actors.map((actor) => (
            <WantedPoster
              key={actor.id}
              id={actor.id}
              name={actor.name}
              aliases={actor.aliases}
              country={actor.country}
              description={actor.description}
              ttpCount={actor.ttp_count}
              toolCount={actor.tool_count}
              targetSectors={actor.target_sectors}
            />
          ))}
        </div>
      )}

      {/* Empty State */}
      {data && data.actors.length === 0 && !isLoading && (
        <Card showAccent stamp="classified">
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <Users className="h-10 w-10 text-steel mb-3" />
            <p className="text-concrete font-mono text-sm">
              {searchQuery || sectorFilter
                ? 'NO MATCHING ACTORS FOUND'
                : 'NO THREAT ACTORS IN DATABASE'}
            </p>
            {(searchQuery || sectorFilter) && (
              <Button
                variant="ghost"
                className="mt-3"
                onClick={() => { setSearchQuery(''); setSectorFilter(''); }}
              >
                Clear filters
              </Button>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}
