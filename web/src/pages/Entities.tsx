/**
 * Entities - Entity database browser with graph visualization
 *
 * Phase 5.3: Spider web graph powered by D3.
 */

import { useState, useEffect, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Card, Button } from '../components/common';
import { SpiderWebGraph, type GraphNode, type GraphLink } from '../components/graph';
import {
  Database, Search, Filter, Globe, Network, Mail,
  Fingerprint, Shield, X, ExternalLink,
} from 'lucide-react';
import { api } from '../api/client';

interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
  total_nodes: number;
  total_links: number;
}

interface EntitySearchResult {
  id: string;
  type: string;
  value: string;
  sources: string[];
  investigation_ids: string[];
}

const ENTITY_TYPE_ICONS: Record<string, typeof Globe> = {
  domain: Globe,
  ip_address: Network,
  email: Mail,
  hash: Fingerprint,
  threat_actor: Shield,
};

export function Entities() {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string | undefined>();
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [containerWidth, setContainerWidth] = useState(900);
  const containerRef = useRef<HTMLDivElement>(null);

  // Responsive width
  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        setContainerWidth(entry.contentRect.width);
      }
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  // Fetch graph data
  const { data: graphData, isLoading: graphLoading } = useQuery<GraphData>({
    queryKey: ['entities', 'graph', filterType],
    queryFn: () => {
      const params = new URLSearchParams();
      if (filterType) params.set('entity_type', filterType);
      params.set('limit', '200');
      return api.get(`/entities/graph?${params}`);
    },
  });

  // Fetch entity type counts
  const { data: typeCounts } = useQuery<{ types: Record<string, number>; total_entities: number }>({
    queryKey: ['entities', 'types'],
    queryFn: () => api.get('/entities/types'),
  });

  // Search entities
  const { data: searchResults } = useQuery<{ results: EntitySearchResult[]; total: number }>({
    queryKey: ['entities', 'search', searchQuery],
    queryFn: () => api.get(`/entities/search?q=${encodeURIComponent(searchQuery)}`),
    enabled: searchQuery.length >= 2,
  });

  const entityTypes = [
    { value: 'domain', label: 'Domains', icon: Globe },
    { value: 'ip_address', label: 'IPs', icon: Network },
    { value: 'email', label: 'Emails', icon: Mail },
    { value: 'hash', label: 'Hashes', icon: Fingerprint },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-display tracking-wider text-paper">
            ENTITY DATABASE
          </h1>
          <p className="text-concrete font-mono text-sm mt-1">
            Intelligence Network Graph &mdash;{' '}
            {typeCounts?.total_entities ?? 0} entities tracked
          </p>
        </div>
      </div>

      {/* Search and Filter Bar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-concrete" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search entities..."
            className="w-full bg-bunker border border-steel pl-10 pr-4 py-2 text-paper font-mono text-sm placeholder:text-steel focus:border-phosphor focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-1">
          <Button
            variant={!filterType ? 'primary' : 'ghost'}
            onClick={() => setFilterType(undefined)}
          >
            All
          </Button>
          {entityTypes.map(({ value, label, icon: Icon }) => (
            <Button
              key={value}
              variant={filterType === value ? 'primary' : 'ghost'}
              onClick={() => setFilterType(filterType === value ? undefined : value)}
            >
              <Icon className="w-3.5 h-3.5 mr-1" />
              {label}
            </Button>
          ))}
        </div>
      </div>

      {/* Search Results */}
      {searchQuery.length >= 2 && searchResults && searchResults.results.length > 0 && (
        <Card title={`Search: "${searchQuery}"`} subtitle={`${searchResults.total} results`}>
          <div className="space-y-1 max-h-48 overflow-y-auto">
            {searchResults.results.map((result) => {
              const Icon = ENTITY_TYPE_ICONS[result.type] || Database;
              return (
                <div
                  key={result.id}
                  className="flex items-center gap-2 px-2 py-1.5 hover:bg-slate font-mono text-sm cursor-pointer"
                  onClick={() => setSelectedNode({
                    id: result.id,
                    label: result.value,
                    type: result.type,
                    properties: {},
                    source_plugins: result.sources,
                    threat_level: 'unknown',
                    investigation_ids: result.investigation_ids,
                  })}
                >
                  <Icon className="w-3.5 h-3.5 text-concrete shrink-0" />
                  <span className="text-paper truncate">{result.value}</span>
                  <span className="text-concrete text-xs ml-auto shrink-0">{result.type}</span>
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* Entity Type Counts */}
      {typeCounts && Object.keys(typeCounts.types).length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {Object.entries(typeCounts.types).map(([type, count]) => {
            const Icon = ENTITY_TYPE_ICONS[type] || Database;
            return (
              <div
                key={type}
                className={`bg-bunker border p-3 cursor-pointer transition-colors ${
                  filterType === type ? 'border-phosphor' : 'border-steel hover:border-concrete'
                }`}
                onClick={() => setFilterType(filterType === type ? undefined : type)}
              >
                <div className="flex items-center gap-2">
                  <Icon className="w-4 h-4 text-concrete" />
                  <span className="font-mono text-xs text-concrete uppercase">{type}</span>
                </div>
                <p className="font-display text-2xl text-paper mt-1">{count}</p>
              </div>
            );
          })}
        </div>
      )}

      {/* Graph Visualization */}
      <div ref={containerRef}>
        <Card title="Intelligence Network" subtitle="Entity relationship graph" showAccent padding="none">
          {graphLoading ? (
            <div className="flex items-center justify-center py-24">
              <div className="text-concrete font-mono text-sm animate-pulse">
                LOADING NETWORK DATA...
              </div>
            </div>
          ) : graphData && graphData.nodes.length > 0 ? (
            <SpiderWebGraph
              nodes={graphData.nodes}
              links={graphData.links}
              width={containerWidth - 2}
              height={500}
              onNodeClick={setSelectedNode}
            />
          ) : (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <Database className="h-10 w-10 text-steel mb-3" />
              <p className="text-concrete font-mono text-sm">
                NO NETWORK DATA AVAILABLE
              </p>
              <p className="text-steel font-mono text-xs mt-1">
                Run an investigation to populate the entity graph
              </p>
            </div>
          )}

          {graphData && graphData.nodes.length > 0 && (
            <div className="px-4 py-2 border-t border-steel flex items-center gap-4 text-xs font-mono text-concrete">
              <span>{graphData.total_nodes} nodes</span>
              <span>{graphData.total_links} connections</span>
              <span className="text-steel">Click node for details &middot; Drag to rearrange &middot; Scroll to zoom</span>
            </div>
          )}
        </Card>
      </div>

      {/* Node Detail Panel */}
      {selectedNode && (
        <Card title="Entity Detail" showAccent>
          <div className="flex items-start justify-between">
            <div className="space-y-3">
              <div>
                <span className="text-xs font-mono text-concrete uppercase">{selectedNode.type}</span>
                <p className="text-paper font-mono text-lg">{selectedNode.label}</p>
              </div>

              {selectedNode.source_plugins.length > 0 && (
                <div>
                  <span className="text-xs font-mono text-concrete">Sources:</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {selectedNode.source_plugins.filter(Boolean).map((p) => (
                      <span key={p} className="text-xs font-mono px-1.5 py-0.5 bg-slate border border-steel text-concrete">
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {selectedNode.investigation_ids.length > 0 && (
                <div>
                  <span className="text-xs font-mono text-concrete">
                    Found in {selectedNode.investigation_ids.length} investigation(s)
                  </span>
                </div>
              )}

              {Object.keys(selectedNode.properties).length > 0 && (
                <div>
                  <span className="text-xs font-mono text-concrete">Properties:</span>
                  <pre className="mt-1 text-xs font-mono text-paper bg-void p-2 border border-steel overflow-auto max-h-32">
                    {JSON.stringify(selectedNode.properties, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            <button
              onClick={() => setSelectedNode(null)}
              className="text-concrete hover:text-paper p-1"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </Card>
      )}
    </div>
  );
}
